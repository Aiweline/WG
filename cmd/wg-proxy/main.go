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
	"crypto/tls"
	"crypto/x509"
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

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: wg-proxy server|client [options]")
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2:])
	case "client":
		client(os.Args[2:])
	default:
		fatalf("usage: wg-proxy server|client [options]")
	}
}

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":9518", "TLS listen address")
	cert := fs.String("cert", "", "PEM certificate path")
	key := fs.String("key", "", "PEM private key path")
	token := fs.String("token", "", "required proxy token")
	fs.Parse(args)
	if *cert == "" || *key == "" || *token == "" {
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
	h := proxyHandler{token: *token, transport: &http.Transport{Proxy: nil}}
	if err := (&http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}).Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatalf("serve: %v", err)
	}
}

func client(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:47101", "loopback HTTP proxy listen address")
	serverAddr := fs.String("server", "", "WG server host:port")
	serverName := fs.String("server-name", "", "TLS server name override (for an SSH test forward)")
	ca := fs.String("ca", "", "PEM server certificate for verification")
	token := fs.String("token", "", "proxy token")
	direct := fs.String("direct-host", "", "comma-separated host suffixes to bypass the tunnel")
	fs.Parse(args)
	if *serverAddr == "" || *ca == "" || *token == "" {
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
	c := clientProxy{server: *serverAddr, token: *token, tls: tlsConfig, direct: splitCSV(*direct)}
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
