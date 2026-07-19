// wg-proxy provides a small, testable WG data plane.
//
// The server is a TLS-protected, token-authenticated HTTP CONNECT proxy. The
// client exposes a loopback HTTP proxy and carries selected requests to the
// server over TLS. It intentionally does not touch DNS, routes, TUN devices,
// or firewall settings.
package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const authHeader = "Bearer "

const (
	udpMagic       = "WGUDP1"
	udpRequest     = byte(1)
	udpResponse    = byte(2)
	maxUDPDatagram = 60 * 1024
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: wg-proxy server|client|udp-server|udp-client [options]")
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2:])
	case "client":
		client(os.Args[2:])
	case "udp-server":
		udpServer(os.Args[2:])
	case "udp-client":
		udpClient(os.Args[2:])
	default:
		fatalf("usage: wg-proxy server|client|udp-server|udp-client [options]")
	}
}

func udpServer(args []string) {
	fs := flag.NewFlagSet("udp-server", flag.ExitOnError)
	listen := fs.String("listen", ":9518", "UDP listen address")
	token := fs.String("token", "", "required UDP token")
	tokenFile := fs.String("token-file", "", "path to the required UDP token file")
	fs.Parse(args)
	resolvedToken, err := loadToken(*token, *tokenFile)
	if err != nil || resolvedToken == "" {
		fatalf("UDP server token: %v", err)
	}
	aead, err := udpAEAD(resolvedToken)
	if err != nil {
		fatalf("UDP server cipher: %v", err)
	}
	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		fatalf("UDP listen address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fatalf("UDP listen: %v", err)
	}
	defer conn.Close()
	log.Printf("WG UDP relay ready udp=%s", conn.LocalAddr())
	buf := make([]byte, maxUDPDatagram)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP read: %v", err)
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		go serveUDPDatagram(conn, peer, packet, aead)
	}
}

func udpClient(args []string) {
	fs := flag.NewFlagSet("udp-client", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:47102", "local UDP relay listen address")
	serverAddr := fs.String("server", "", "WG UDP server host:port")
	target := fs.String("target", "", "required UDP destination host:port")
	token := fs.String("token", "", "required UDP token")
	tokenFile := fs.String("token-file", "", "path to the required UDP token file")
	fs.Parse(args)
	resolvedToken, err := loadToken(*token, *tokenFile)
	if err != nil || *serverAddr == "" || *target == "" || resolvedToken == "" {
		fatalf("UDP client requires -server, -target, and token: %v", err)
	}
	aead, err := udpAEAD(resolvedToken)
	if err != nil {
		fatalf("UDP client cipher: %v", err)
	}
	server, err := net.ResolveUDPAddr("udp", *serverAddr)
	if err != nil {
		fatalf("UDP server address: %v", err)
	}
	local, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		fatalf("UDP listen address: %v", err)
	}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		fatalf("UDP listen: %v", err)
	}
	defer conn.Close()
	log.Printf("WG UDP client ready relay=%s server=%s target=%s", conn.LocalAddr(), server, *target)
	buf := make([]byte, maxUDPDatagram)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP local read: %v", err)
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		go relayUDPDatagram(conn, peer, server, *target, payload, aead)
	}
}

func udpAEAD(token string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(token))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealUDP(aead cipher.AEAD, payload []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	packet := make([]byte, 0, len(udpMagic)+len(nonce)+len(payload)+aead.Overhead())
	packet = append(packet, udpMagic...)
	packet = append(packet, nonce...)
	return aead.Seal(packet, nonce, payload, nil), nil
}

func openUDP(aead cipher.AEAD, packet []byte) ([]byte, error) {
	if len(packet) < len(udpMagic)+aead.NonceSize()+aead.Overhead() || string(packet[:len(udpMagic)]) != udpMagic {
		return nil, errors.New("invalid UDP packet")
	}
	nonce := packet[len(udpMagic) : len(udpMagic)+aead.NonceSize()]
	return aead.Open(nil, nonce, packet[len(udpMagic)+aead.NonceSize():], nil)
}

func serveUDPDatagram(listener *net.UDPConn, peer *net.UDPAddr, packet []byte, aead cipher.AEAD) {
	payload, err := openUDP(aead, packet)
	if err != nil {
		return
	}
	target, body, err := parseUDPRequest(payload)
	if err != nil {
		return
	}
	upstream, err := net.DialTimeout("udp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(body); err != nil {
		return
	}
	_ = upstream.SetReadDeadline(time.Now().Add(15 * time.Second))
	response := make([]byte, maxUDPDatagram)
	n, err := upstream.Read(response)
	if err != nil {
		return
	}
	sealed, err := sealUDP(aead, append([]byte{udpResponse}, response[:n]...))
	if err == nil {
		_, _ = listener.WriteToUDP(sealed, peer)
		log.Printf("route=udp target=%s bytes=%d", target, n)
	}
}

func relayUDPDatagram(listener *net.UDPConn, peer, server *net.UDPAddr, target string, body []byte, aead cipher.AEAD) {
	payload, err := makeUDPRequest(target, body)
	if err != nil {
		return
	}
	packet, err := sealUDP(aead, payload)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, server)
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := conn.Write(packet); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	response := make([]byte, maxUDPDatagram)
	n, err := conn.Read(response)
	if err != nil {
		return
	}
	plain, err := openUDP(aead, response[:n])
	if err != nil || len(plain) < 1 || plain[0] != udpResponse {
		return
	}
	_, _ = listener.WriteToUDP(plain[1:], peer)
}

func makeUDPRequest(target string, body []byte) ([]byte, error) {
	if _, _, err := net.SplitHostPort(target); err != nil || len(target) > 0xffff {
		return nil, errors.New("UDP target must be host:port")
	}
	payload := make([]byte, 3+len(target)+len(body))
	payload[0] = udpRequest
	binary.BigEndian.PutUint16(payload[1:3], uint16(len(target)))
	copy(payload[3:], target)
	copy(payload[3+len(target):], body)
	return payload, nil
}

func parseUDPRequest(payload []byte) (string, []byte, error) {
	if len(payload) < 3 || payload[0] != udpRequest {
		return "", nil, errors.New("invalid UDP request")
	}
	n := int(binary.BigEndian.Uint16(payload[1:3]))
	if n == 0 || len(payload) < 3+n {
		return "", nil, errors.New("invalid UDP target")
	}
	target := string(payload[3 : 3+n])
	if _, _, err := net.SplitHostPort(target); err != nil {
		return "", nil, errors.New("invalid UDP target")
	}
	return target, payload[3+n:], nil
}

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":9518", "TLS listen address")
	cert := fs.String("cert", "", "PEM certificate path")
	key := fs.String("key", "", "PEM private key path")
	token := fs.String("token", "", "required proxy token")
	tokenFile := fs.String("token-file", "", "path to the required proxy token file")
	fs.Parse(args)
	resolvedToken, err := loadToken(*token, *tokenFile)
	if err != nil {
		fatalf("server token: %v", err)
	}
	if *cert == "" || *key == "" || resolvedToken == "" {
		fatalf("server requires -cert, -key, and -token")
	}
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fatalf("load TLS certificate: %v", err)
	}
	listener, err := tls.Listen("tcp", *listen, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	if err != nil {
		fatalf("listen: %v", err)
	}
	log.Printf("WG data plane server ready tls=%s", listener.Addr())
	h := proxyHandler{token: resolvedToken, transport: &http.Transport{Proxy: nil}}
	if err := (&http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}).Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatalf("serve: %v", err)
	}
}

func loadToken(token, tokenFile string) (string, error) {
	token = strings.TrimSpace(token)
	tokenFile = strings.TrimSpace(tokenFile)
	if token != "" && tokenFile != "" {
		return "", errors.New("choose either -token or -token-file")
	}
	if tokenFile == "" {
		return token, nil
	}
	contents, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	return strings.TrimSpace(string(contents)), nil
}

func client(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:47101", "loopback HTTP proxy listen address")
	serverAddr := fs.String("server", "", "WG server host:port")
	serverName := fs.String("server-name", "", "TLS server name override (for an SSH test forward)")
	ca := fs.String("ca", "", "PEM server certificate for verification")
	token := fs.String("token", "", "proxy token")
	tokenFile := fs.String("token-file", "", "path to the proxy token file")
	direct := fs.String("direct-host", "", "comma-separated host suffixes to bypass the tunnel")
	fs.Parse(args)
	resolvedToken, err := loadToken(*token, *tokenFile)
	if err != nil {
		fatalf("client token: %v", err)
	}
	if *serverAddr == "" || *ca == "" || resolvedToken == "" {
		fatalf("client requires -server, -ca, and -token")
	}
	pem, err := os.ReadFile(*ca)
	if err != nil {
		fatalf("read CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		fatalf("read CA: no certificate found")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatalf("listen: %v", err)
	}
	log.Printf("WG client ready proxy=%s server=%s", ln.Addr(), *serverAddr)
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if *serverName != "" {
		tlsConfig.ServerName = *serverName
	}
	c := clientProxy{server: *serverAddr, token: resolvedToken, tls: tlsConfig, direct: splitCSV(*direct)}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go c.serve(conn)
	}
}

type proxyHandler struct {
	token     string
	transport *http.Transport
}

func (h proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Proxy-Authorization") != authHeader+h.token {
		w.Header().Set("Proxy-Authenticate", "Bearer")
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		h.connect(w, r)
		return
	}
	r.RequestURI = ""
	stripHopHeaders(r.Header)
	resp, err := h.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	log.Printf("route=tunnel method=%s host=%s status=%d", r.Method, r.URL.Host, resp.StatusCode)
}

func (h proxyHandler) connect(w http.ResponseWriter, r *http.Request) {
	// Prefer IPv4 for the tunnel data plane. Some VPS hosts publish AAAA records
	// through DNS but do not have an IPv6 default route; using tcp4 avoids a long
	// failed IPv6 attempt before a healthy IPv4 connection can be made.
	upstream, err := net.DialTimeout("tcp4", ensurePort(r.Host), 10*time.Second)
	if err != nil {
		http.Error(w, "connect upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = rw.Flush()
	log.Printf("route=tunnel connect=%s", r.Host)
	bridge(clientConn, upstream)
}

type clientProxy struct {
	server, token string
	tls           *tls.Config
	direct        []string
}

func (c clientProxy) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	host := requestHost(req)
	if matches(host, c.direct) {
		log.Printf("route=direct host=%s", host)
		serveDirect(conn, reader, req)
		return
	}
	log.Printf("route=tunnel host=%s", host)
	tunnel, err := tls.Dial("tcp", c.server, c.tls)
	if err != nil {
		writeProxyError(conn, "tunnel: "+err.Error())
		return
	}
	defer tunnel.Close()
	req.Header.Set("Proxy-Authorization", authHeader+c.token)
	// WriteProxy preserves the absolute request target and Proxy-Authorization
	// header expected by the remote HTTP proxy. Request.Write serializes an
	// origin-form request, which makes a remote proxy lose the target scheme.
	if err := req.WriteProxy(tunnel); err != nil {
		return
	}
	// The server response (including CONNECT's 200 line) must be copied byte for
	// byte. Parsing and serializing it again can change hop-by-hop semantics and
	// caused clients to observe a reset after a successful CONNECT handshake.
	bridgeWithReaders(conn, reader, tunnel, nil)
}

func serveDirect(conn net.Conn, reader *bufio.Reader, req *http.Request) {
	if req.Method == http.MethodConnect {
		upstream, err := net.DialTimeout("tcp4", ensurePort(req.Host), 10*time.Second)
		if err != nil {
			writeProxyError(conn, err.Error())
			return
		}
		defer upstream.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		bridgeWithReaders(conn, reader, upstream, nil)
		return
	}
	req.RequestURI = ""
	stripHopHeaders(req.Header)
	resp, err := (&http.Transport{Proxy: nil}).RoundTrip(req)
	if err != nil {
		writeProxyError(conn, err.Error())
		return
	}
	defer resp.Body.Close()
	_ = resp.Write(conn)
}

func bridge(a, b net.Conn) { bridgeWithReaders(a, nil, b, nil) }
func bridgeWithReaders(a net.Conn, ar *bufio.Reader, b net.Conn, br *bufio.Reader) {
	var wg sync.WaitGroup
	copySide := func(dst net.Conn, src net.Conn, r *bufio.Reader) {
		defer wg.Done()
		if r != nil {
			_, _ = io.Copy(dst, r)
		} else {
			_, _ = io.Copy(dst, src)
		}
		_ = dst.Close()
	}
	wg.Add(2)
	go copySide(b, a, ar)
	go copySide(a, b, br)
	wg.Wait()
}

func splitCSV(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(strings.TrimPrefix(v, ".")); v != "" {
			out = append(out, strings.ToLower(v))
		}
	}
	return out
}
func matches(host string, rules []string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.Split(host, ":")[0], "."))
	for _, rule := range rules {
		if host == rule || strings.HasSuffix(host, "."+rule) {
			return true
		}
	}
	return false
}
func requestHost(r *http.Request) string {
	if r.Method == http.MethodConnect {
		return r.Host
	}
	if r.URL != nil && r.URL.Host != "" {
		return r.URL.Host
	}
	return r.Host
}
func ensurePort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "443")
}
func stripHopHeaders(h http.Header) {
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(key)
	}
}
func copyHeader(dst, src http.Header) {
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}
func writeProxyError(w io.Writer, message string) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(message), message)
}
func fatalf(format string, args ...any) { log.Print(fmt.Sprintf(format, args...)); os.Exit(2) }

var _ = context.Background
var _ = url.URL{}
