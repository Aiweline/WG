package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
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
	staticHandler := newSPAHandler(root)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
