package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"wg.local/wg/internal/app"
	"wg.local/wg/internal/controlapi"
	"wg.local/wg/internal/platform"
	"wg.local/wg/internal/privatedns"
)

var version = "0.1.0-dev"

type options struct {
	mode              string
	managementAddress string
	dataAddress       string
	endpoint          string
	devSafe           bool
	noHostNetwork     bool
	instance          string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("wg-core stopped", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	options, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	if !options.devSafe || !options.noHostNetwork {
		return errors.New("production networking is not implemented; start with --dev-safe --no-host-network")
	}
	if os.Getenv("WG_DEV_SAFE") != "1" {
		slog.Warn("WG_DEV_SAFE is not set; command-line safety flags still keep host networking disabled")
	}
	if err := validateLoopback(options.managementAddress); err != nil {
		return err
	}

	dnsSource := platform.ResolverSource{}
	initialDNS, dnsErr := dnsSource.ReadSnapshot(context.Background())
	if dnsErr != nil {
		slog.Warn("read-only DNS snapshot is degraded", "error", dnsErr)
		initialDNS = privatedns.Snapshot{CapturedAt: time.Now().UTC(), Metadata: map[string]string{"source": "/etc/resolv.conf", "adapter": "read-only-resolv-conf"}}
	}
	service := app.NewService(app.Config{
		Mode: options.mode, Endpoint: options.endpoint, InitialDNS: initialDNS, DNSSource: dnsSource,
		Versions: controlapi.Versions{Bundle: version, UI: version, Core: version, Scripts: version},
	})
	api := controlapi.NewServer(service, slog.Default())
	listener, err := net.Listen("tcp", options.managementAddress)
	if err != nil {
		return fmt.Errorf("listen on local management address: %w", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler: api.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
	}
	errorChannel := make(chan error, 1)
	go func() {
		slog.Info("WG safe development core is ready",
			"mode", options.mode, "management", listener.Addr().String(), "instance", options.instance,
			"host_network_changes", false, "data_listener", false, "configured_data_address", options.dataAddress)
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
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	}
}

func parseOptions(arguments []string) (options, error) {
	if len(arguments) == 0 || arguments[0] == "help" || arguments[0] == "--help" || arguments[0] == "-h" {
		return options{}, errors.New("usage: wg-core client|server --dev-safe --no-host-network [options]")
	}
	mode := strings.ToLower(arguments[0])
	if mode != "client" && mode != "server" {
		return options{}, fmt.Errorf("mode must be client or server, got %q", arguments[0])
	}
	defaultManagement := "127.0.0.1:47003"
	if mode == "server" {
		defaultManagement = "127.0.0.1:47002"
	}
	value := options{mode: mode, managementAddress: defaultManagement, dataAddress: "0.0.0.0:9518", endpoint: "203.0.113.10:9518"}
	flags := flag.NewFlagSet("wg-core "+mode, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&value.managementAddress, "management-address", value.managementAddress, "loopback development management address")
	flags.StringVar(&value.dataAddress, "listen", value.dataAddress, "configured data address (not opened in safe development mode)")
	flags.StringVar(&value.endpoint, "endpoint", value.endpoint, "client server endpoint")
	flags.BoolVar(&value.devSafe, "dev-safe", false, "enable safe development mode")
	flags.BoolVar(&value.noHostNetwork, "no-host-network", false, "forbid TUN, routes, firewall, forwarding, DNS, and service changes")
	flags.StringVar(&value.instance, "wg-dev-instance", mode, "development process identity")
	if err := flags.Parse(arguments[1:]); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	return value, nil
}

func validateLoopback(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("management address must be host:port: %w", err)
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || !parsed.IsLoopback() {
		return fmt.Errorf("management address must use a literal loopback IP, got %q", address)
	}
	if port == "" {
		return errors.New("management port is required")
	}
	return nil
}
