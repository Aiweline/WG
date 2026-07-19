package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("wg-client-ui stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	listenAddress := flag.String("listen", "127.0.0.1:4173", "loopback UI address")
	assetsPath := flag.String("assets", "ui/client/dist", "built UI asset directory")
	coreURL := flag.String("core", "http://127.0.0.1:47003", "loopback wg-core URL")
	flag.Parse()
	if err := requireLoopback(*listenAddress); err != nil {
		return err
	}
	target, err := url.Parse(*coreURL)
	if err != nil || target.Scheme != "http" || target.Hostname() == "" {
		return fmt.Errorf("invalid core URL %q", *coreURL)
	}
	if err := requireLoopback(target.Host); err != nil {
		return fmt.Errorf("core URL: %w", err)
	}
	root, err := filepath.Abs(*assetsPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, "index.html")); err != nil {
		return fmt.Errorf("UI is not built at %s; run npm run build in ui/client: %w", root, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, proxyErr error) {
		slog.Warn("wg-core is unavailable", "error", proxyErr)
		http.Error(w, `{"error":{"code":"backend_unavailable","message":"wg-core is unavailable"}}`, http.StatusBadGateway)
	}
	proxyTests := newProxyTestHandler()
	staticHandler := newSPAHandler(root)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/proxy/status" {
			proxyTests.status(w, r)
			return
		}
		if r.URL.Path == "/api/proxy/test" {
			proxyTests.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1" {
			proxy.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		staticHandler.ServeHTTP(w, r)
	})
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second}
	errorChannel := make(chan error, 1)
	go func() {
		slog.Info("WG client UI is ready", "url", "http://"+listener.Addr().String(), "core", target.String())
		errorChannel <- server.Serve(listener)
	}()

	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errorChannel:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdownSignal.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

type proxyTestHandler struct {
	dnsFingerprint string
	dnsAvailable   bool
}

type proxyTestResult struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
	ExitIP string `json:"exit_ip,omitempty"`
}

type proxyTestReport struct {
	GeneratedAt time.Time       `json:"generated_at"`
	TCP         proxyTestResult `json:"tcp"`
	UDP         proxyTestResult `json:"udp"`
	SystemDNS   proxyTestResult `json:"system_dns"`
}

func newProxyTestHandler() proxyTestHandler {
	fingerprint, err := systemDNSFingerprint()
	return proxyTestHandler{dnsFingerprint: fingerprint, dnsAvailable: err == nil}
}

func (h proxyTestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	report := proxyTestReport{GeneratedAt: time.Now().UTC(), TCP: testTCPProxy(), UDP: testUDPRelay(), SystemDNS: h.testSystemDNS()}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(report)
}

func (h proxyTestHandler) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	tcp := portListening("tcp", "127.0.0.1:47101")
	udp := udpPortOccupied("127.0.0.1:47102")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"tcp_listener": tcp, "udp_listener": udp})
}

func portListening(network, address string) bool {
	conn, err := net.DialTimeout(network, address, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func udpPortOccupied(address string) bool {
	udpAddress, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return false
	}
	conn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return true
	}
	_ = conn.Close()
	return false
}

func testTCPProxy() proxyTestResult {
	proxyURL, _ := url.Parse("http://127.0.0.1:47101")
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	response, err := client.Get("https://icanhazip.com")
	if err != nil {
		return proxyTestResult{State: "failed", Detail: "TCP 代理不可用：" + err.Error()}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil || response.StatusCode != http.StatusOK {
		return proxyTestResult{State: "failed", Detail: "TCP 代理请求未成功"}
	}
	exitIP := strings.TrimSpace(string(body))
	if net.ParseIP(exitIP) == nil {
		return proxyTestResult{State: "failed", Detail: "TCP 代理返回了无效出口地址"}
	}
	return proxyTestResult{State: "passed", Detail: "已通过 HTTPS CONNECT 实际访问出口探针", ExitIP: exitIP}
}

func testUDPRelay() proxyTestResult {
	connection, err := net.DialTimeout("udp", "127.0.0.1:47102", 2*time.Second)
	if err != nil {
		return proxyTestResult{State: "failed", Detail: "UDP 中继不可用：" + err.Error()}
	}
	defer connection.Close()
	query, id := dnsQuery("example.com")
	if _, err := connection.Write(query); err != nil {
		return proxyTestResult{State: "failed", Detail: "无法写入 UDP 中继"}
	}
	_ = connection.SetReadDeadline(time.Now().Add(15 * time.Second))
	response := make([]byte, 4096)
	n, err := connection.Read(response)
	if err != nil || !validDNSResponse(response[:n], id) {
		return proxyTestResult{State: "failed", Detail: "UDP DNS 请求未获得有效响应"}
	}
	return proxyTestResult{State: "passed", Detail: "已通过加密 UDP 中继解析 example.com"}
}

func (h proxyTestHandler) testSystemDNS() proxyTestResult {
	if !h.dnsAvailable {
		return proxyTestResult{State: "unavailable", Detail: "当前平台无法读取系统 DNS 指纹"}
	}
	current, err := systemDNSFingerprint()
	if err != nil {
		return proxyTestResult{State: "failed", Detail: "无法读取系统 DNS 状态"}
	}
	if current != h.dnsFingerprint {
		return proxyTestResult{State: "failed", Detail: "UI 启动后系统 DNS 已发生变化"}
	}
	return proxyTestResult{State: "passed", Detail: "UI 启动后系统 DNS 未变化"}
}

func systemDNSFingerprint() (string, error) {
	output, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(output)
	return hex.EncodeToString(digest[:]), nil
}

func dnsQuery(name string) ([]byte, uint16) {
	var randomID [2]byte
	_, _ = rand.Read(randomID[:])
	id := binary.BigEndian.Uint16(randomID[:])
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[:2], id)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	return query, id
}

func validDNSResponse(response []byte, id uint16) bool {
	return len(response) >= 12 && binary.BigEndian.Uint16(response[:2]) == id && response[2]&0x80 != 0 && response[3]&0x0f == 0 && binary.BigEndian.Uint16(response[6:8]) > 0
}

func newSPAHandler(root string) http.Handler {
	rootFS := os.DirFS(root)
	files := http.FileServer(http.FS(rootFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if requested == "." || requested == "" {
			requested = "index.html"
		}
		if fs.ValidPath(requested) {
			if info, err := fs.Stat(rootFS, requested); err == nil && !info.IsDir() {
				if requested == "index.html" {
					r.URL.Path = "/"
				} else {
					r.URL.Path = "/" + requested
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		r.URL.Path = "/"
		files.ServeHTTP(w, r)
	})
}

func requireLoopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("address must be host:port: %w", err)
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || !parsed.IsLoopback() {
		return fmt.Errorf("address must use a literal loopback IP, got %q", address)
	}
	return nil
}
