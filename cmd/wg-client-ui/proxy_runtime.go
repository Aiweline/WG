package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxProxyConfigBytes int64 = 64 << 10

type proxyServerProfile struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type proxyClientConfig struct {
	Servers          []proxyServerProfile `json:"servers"`
	SelectedEndpoint string               `json:"selected_endpoint"`
	Transport        string               `json:"transport"`
	UDPTarget        string               `json:"udp_target"`
}

type proxyRuntimeStatus struct {
	Configured       bool                 `json:"configured"`
	Connected        bool                 `json:"connected"`
	TCPListener      bool                 `json:"tcp_listener"`
	UDPListener      bool                 `json:"udp_listener"`
	Managed          bool                 `json:"managed"`
	SelectedEndpoint string               `json:"selected_endpoint"`
	Transport        string               `json:"transport"`
	UDPTarget        string               `json:"udp_target"`
	Servers          []proxyServerProfile `json:"servers"`
	StartedAt        *time.Time           `json:"started_at,omitempty"`
}

type managedProxyProcess struct {
	command *exec.Cmd
	done    chan error
	logFile *os.File
}

type proxyController struct {
	mu        sync.Mutex
	stateDir  string
	binary    string
	tcp       *managedProxyProcess
	udp       *managedProxyProcess
	startedAt *time.Time
}

func newProxyController(stateDir, binary string) *proxyController {
	return &proxyController{stateDir: stateDir, binary: binary}
}

func defaultProxyStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".wg-client"), nil
}

func defaultProxyBinary() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(executable), "wg-proxy"), nil
}

func (c *proxyController) configPath() string { return filepath.Join(c.stateDir, "config.json") }

func defaultProxyConfig() proxyClientConfig {
	return proxyClientConfig{Transport: "tcp", UDPTarget: "1.1.1.1:53", Servers: []proxyServerProfile{}}
}

func (c *proxyController) loadConfig() (proxyClientConfig, error) {
	configFile, err := os.Open(c.configPath())
	if errors.Is(err, os.ErrNotExist) {
		return defaultProxyConfig(), nil
	}
	if err != nil {
		return proxyClientConfig{}, err
	}
	defer configFile.Close()
	contents, err := io.ReadAll(io.LimitReader(configFile, maxProxyConfigBytes+1))
	if err != nil {
		return proxyClientConfig{}, err
	}
	if int64(len(contents)) > maxProxyConfigBytes {
		return proxyClientConfig{}, errors.New("proxy config exceeds 64 KiB")
	}
	config, err := decodeProxyConfig(strings.NewReader(string(contents)))
	if err != nil {
		return proxyClientConfig{}, fmt.Errorf("read proxy config: %w", err)
	}
	if err := validateProxyConfig(config, false); err != nil {
		return proxyClientConfig{}, err
	}
	return config, nil
}

func (c *proxyController) saveConfig(config proxyClientConfig) error {
	if err := validateProxyConfig(config, false); err != nil {
		return err
	}
	if err := c.ensureStateDir(); err != nil {
		return err
	}
	contents, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if int64(len(contents)) > maxProxyConfigBytes {
		return errors.New("proxy config exceeds 64 KiB")
	}
	temporary, err := os.CreateTemp(c.stateDir, "config-*.json")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, c.configPath()); err != nil {
		return err
	}
	committed = true
	return nil
}

func decodeProxyConfig(reader io.Reader) (proxyClientConfig, error) {
	config := defaultProxyConfig()
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return proxyClientConfig{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return proxyClientConfig{}, errors.New("proxy config must contain exactly one JSON object")
		}
		return proxyClientConfig{}, err
	}
	return config, nil
}

func (c *proxyController) ensureStateDir() error {
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(c.stateDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("proxy state path is not a directory: %s", c.stateDir)
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(c.stateDir, 0o700); err != nil {
			return fmt.Errorf("secure proxy state directory: %w", err)
		}
	}
	return nil
}

func validateProxyConfig(config proxyClientConfig, requireSelection bool) error {
	switch config.Transport {
	case "tcp", "udp", "both":
	default:
		return errors.New("传输模式必须是 tcp、udp 或 both")
	}
	if len(config.Servers) > 32 {
		return errors.New("服务器数量不能超过 32 个")
	}
	seen := map[string]struct{}{}
	selectedFound := false
	for index, server := range config.Servers {
		server.Name = strings.TrimSpace(server.Name)
		address, err := netip.ParseAddr(strings.TrimSpace(server.IP))
		if err != nil {
			return fmt.Errorf("第 %d 个服务器 IP 无效", index+1)
		}
		if address.IsUnspecified() || address.IsMulticast() {
			return fmt.Errorf("第 %d 个服务器 IP 不可用", index+1)
		}
		if server.Port < 1 || server.Port > 65535 {
			return fmt.Errorf("第 %d 个服务器端口无效", index+1)
		}
		endpoint := net.JoinHostPort(address.String(), fmt.Sprintf("%d", server.Port))
		if _, exists := seen[endpoint]; exists {
			return errors.New("服务器列表包含重复地址")
		}
		seen[endpoint] = struct{}{}
		if endpoint == config.SelectedEndpoint {
			selectedFound = true
		}
	}
	if config.SelectedEndpoint != "" && !selectedFound {
		return errors.New("选择的服务器不在服务器列表中")
	}
	if requireSelection && config.SelectedEndpoint == "" {
		return errors.New("请选择一个已配置的服务器")
	}
	if (config.Transport == "udp" || config.Transport == "both") && !validHostPort(config.UDPTarget) {
		return errors.New("UDP 目标必须是 host:port")
	}
	return nil
}

func validHostPort(value string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || strings.TrimSpace(host) == "" || port == "" || strings.ContainsAny(host, " \t\r\n/\\") {
		return false
	}
	for _, character := range port {
		if character < '0' || character > '9' {
			return false
		}
	}
	numericPort, err := strconv.Atoi(port)
	return err == nil && numericPort >= 1 && numericPort <= 65535
}

func (c *proxyController) status() proxyRuntimeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	config, err := c.loadConfig()
	if err != nil {
		config = defaultProxyConfig()
	}
	tcp := portListening("tcp", "127.0.0.1:47101")
	udp := udpPortOccupied("127.0.0.1:47102")
	connected := false
	switch config.Transport {
	case "tcp":
		connected = tcp
	case "udp":
		connected = udp
	case "both":
		connected = tcp && udp
	}
	return proxyRuntimeStatus{
		Configured: config.SelectedEndpoint != "", Connected: connected, TCPListener: tcp, UDPListener: udp,
		Managed: c.tcp != nil || c.udp != nil, SelectedEndpoint: config.SelectedEndpoint, Transport: config.Transport,
		UDPTarget: config.UDPTarget, Servers: config.Servers, StartedAt: c.startedAt,
	}
}

func (c *proxyController) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	config, err := c.loadConfig()
	if err != nil {
		return err
	}
	if err := validateProxyConfig(config, true); err != nil {
		return err
	}
	binaryInfo, err := os.Stat(c.binary)
	if err != nil {
		return fmt.Errorf("找不到代理程序 %s，请先运行 make build", c.binary)
	}
	if !binaryInfo.Mode().IsRegular() {
		return fmt.Errorf("代理程序不是普通文件: %s", c.binary)
	}
	certificate := filepath.Join(c.stateDir, "server-cert.pem")
	token := filepath.Join(c.stateDir, "token")
	certificateInfo, err := os.Stat(certificate)
	if err != nil || !certificateInfo.Mode().IsRegular() {
		return fmt.Errorf("缺少服务器证书 %s", certificate)
	}
	tokenInfo, err := os.Stat(token)
	if err != nil || !tokenInfo.Mode().IsRegular() {
		return fmt.Errorf("缺少代理令牌 %s", token)
	}
	if tokenInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("代理令牌权限不安全，请执行 chmod 600 %s", token)
	}
	if c.tcp != nil || c.udp != nil {
		if err := c.stopLocked(); err != nil {
			return err
		}
	}
	if (config.Transport == "tcp" || config.Transport == "both") && portListening("tcp", "127.0.0.1:47101") {
		return errors.New("TCP 代理端口 127.0.0.1:47101 已被其他进程占用")
	}
	if (config.Transport == "udp" || config.Transport == "both") && udpPortOccupied("127.0.0.1:47102") {
		return errors.New("UDP 中继端口 127.0.0.1:47102 已被其他进程占用")
	}
	if config.Transport == "tcp" || config.Transport == "both" {
		c.tcp, err = c.startProcess("tcp", "client", "-listen", "127.0.0.1:47101", "-server", config.SelectedEndpoint, "-ca", certificate, "-token-file", token)
		if err != nil {
			return err
		}
	}
	if config.Transport == "udp" || config.Transport == "both" {
		c.udp, err = c.startProcess("udp", "udp-client", "-listen", "127.0.0.1:47102", "-server", config.SelectedEndpoint, "-target", config.UDPTarget, "-token-file", token)
		if err != nil {
			_ = c.stopLocked()
			return err
		}
	}
	if c.tcp != nil && !waitForProxyListener(3*time.Second, func() bool {
		return portListening("tcp", "127.0.0.1:47101")
	}) {
		_ = c.stopLocked()
		return errors.New("TCP 代理启动失败，请查看本机日志")
	}
	if c.udp != nil && !waitForProxyListener(3*time.Second, func() bool {
		return udpPortOccupied("127.0.0.1:47102")
	}) {
		_ = c.stopLocked()
		return errors.New("UDP 中继启动失败，请查看本机日志")
	}
	now := time.Now().UTC()
	c.startedAt = &now
	return nil
}

func waitForProxyListener(timeout time.Duration, ready func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if ready() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (c *proxyController) startProcess(name string, args ...string) (*managedProxyProcess, error) {
	if err := c.ensureStateDir(); err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(filepath.Join(c.stateDir, name+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	command := exec.Command(c.binary, args...)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	process := &managedProxyProcess{command: command, done: make(chan error, 1), logFile: logFile}
	go func() {
		process.done <- command.Wait()
		_ = logFile.Close()
	}()
	return process, nil
}

func (c *proxyController) disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopLocked()
}

func (c *proxyController) stopLocked() error {
	var stopErr error
	for _, process := range []*managedProxyProcess{c.tcp, c.udp} {
		if process == nil || process.command.Process == nil {
			continue
		}
		if err := process.command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			stopErr = errors.Join(stopErr, err)
		}
		select {
		case <-process.done:
		case <-time.After(2 * time.Second):
			if err := process.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				stopErr = errors.Join(stopErr, err)
			}
		}
	}
	c.tcp = nil
	c.udp = nil
	c.startedAt = nil
	return stopErr
}

func (c *proxyController) close() { _ = c.disconnect() }

func (c *proxyController) serveStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeProxyAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeProxyJSON(w, http.StatusOK, c.status())
}

func (c *proxyController) serveConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config, err := c.loadConfig()
		if err != nil {
			writeProxyAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeProxyJSON(w, http.StatusOK, config)
	case http.MethodPut:
		config, err := decodeProxyConfig(http.MaxBytesReader(w, r.Body, maxProxyConfigBytes))
		if err != nil {
			writeProxyAPIError(w, http.StatusBadRequest, "配置格式无效")
			return
		}
		if err := c.saveConfig(config); err != nil {
			writeProxyAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeProxyJSON(w, http.StatusOK, config)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPut)
		writeProxyAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (c *proxyController) serveConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeProxyAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := c.connect(); err != nil {
		writeProxyAPIError(w, http.StatusConflict, err.Error())
		return
	}
	writeProxyJSON(w, http.StatusOK, c.status())
}

func (c *proxyController) serveDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeProxyAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := c.disconnect(); err != nil {
		writeProxyAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeProxyJSON(w, http.StatusOK, c.status())
}

func (c *proxyController) serveReconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeProxyAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := c.disconnect(); err != nil {
		writeProxyAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := c.connect(); err != nil {
		writeProxyAPIError(w, http.StatusConflict, err.Error())
		return
	}
	writeProxyJSON(w, http.StatusOK, c.status())
}

func writeProxyJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeProxyAPIError(w http.ResponseWriter, status int, message string) {
	writeProxyJSON(w, status, map[string]any{"error": map[string]string{"message": message}})
}
