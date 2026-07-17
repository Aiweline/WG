// Package platform contains narrow, read-only operating-system adapters.
package platform

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"wg.local/wg/internal/privatedns"
)

// ResolverSource reads /etc/resolv.conf without changing it. It is a safe
// baseline adapter for development and simple Linux hosts. Production builds
// still need native per-link adapters for systemd-resolved and NetworkManager.
type ResolverSource struct {
	Path string
}

func (s ResolverSource) ReadSnapshot(ctx context.Context) (privatedns.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return privatedns.Snapshot{}, err
	}
	path := s.Path
	if path == "" {
		path = "/etc/resolv.conf"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return privatedns.Snapshot{}, fmt.Errorf("read resolver snapshot: %w", err)
	}
	snapshot, err := ParseResolverConfig(string(data))
	if err != nil {
		return privatedns.Snapshot{}, err
	}
	snapshot.CapturedAt = time.Now().UTC()
	snapshot.Metadata["source"] = path
	snapshot.Metadata["adapter"] = "read-only-resolv-conf"
	return snapshot, nil
}

// ParseResolverConfig parses only nameserver and search/domain lines. It never
// resolves names and cannot touch the system resolver or its cache.
func ParseResolverConfig(contents string) (privatedns.Snapshot, error) {
	snapshot := privatedns.Snapshot{Metadata: map[string]string{}}
	localOnly := 0
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			address, port, err := parseNameserver(fields[1])
			if err != nil {
				continue
			}
			if address.IsLoopback() {
				localOnly++
				continue
			}
			snapshot.Upstreams = append(snapshot.Upstreams, privatedns.Upstream{
				Address: address.String(), Port: port, Transport: "system-policy",
			})
		case "search", "domain":
			for _, domain := range fields[1:] {
				domain = strings.TrimSuffix(strings.ToLower(domain), ".")
				if domain != "" {
					snapshot.SearchDomains = append(snapshot.SearchDomains, domain)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return privatedns.Snapshot{}, fmt.Errorf("scan resolver snapshot: %w", err)
	}
	if localOnly > 0 {
		snapshot.Metadata["local_proxy_omitted"] = strconv.Itoa(localOnly)
	}
	if len(snapshot.Upstreams) == 0 {
		if localOnly > 0 {
			return snapshot, errors.New("resolver exposes only a local proxy; native per-link expansion is required")
		}
		return snapshot, errors.New("resolver snapshot has no usable upstreams")
	}
	return snapshot, nil
}

func parseNameserver(value string) (netip.Addr, uint16, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap(), 53, nil
	}
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return endpoint.Addr().Unmap(), endpoint.Port(), nil
}
