package singbox

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	// ClashAPI is the base URL for the Clash API.
	ClashAPI = envOr("MACFLOW_CLASH_API", "http://127.0.0.1:9090")

	// ConfigPath is where sing-box config is written.
	ConfigPath = envOr("MACFLOW_SINGBOX_CONFIG", "/etc/sing-box/config.json")

	clashClient = &http.Client{Timeout: 5 * time.Second}

	// TestURLs for delay testing (tried in order).
	TestURLs = []string{
		"http://www.gstatic.com/generate_204",
		"http://cp.cloudflare.com",
		"http://www.google.com/generate_204",
	}
)

// GetSelectorState returns (current_tag, all_options, error).
func GetSelectorState() (string, []string, error) {
	resp, err := clashClient.Get(ClashAPI + "/proxies/proxy-select")
	if err != nil {
		return "", nil, fmt.Errorf("clash API unreachable: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Now  string   `json:"now"`
		All  []string `json:"all"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, err
	}
	return result.Now, result.All, nil
}

// SetSelector switches the proxy-select selector to the given tag.
func SetSelector(tag string) error {
	body := fmt.Sprintf(`{"name":"%s"}`, tag)
	req, _ := http.NewRequest("PUT", ClashAPI+"/proxies/proxy-select",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := clashClient.Do(req)
	if err != nil {
		return fmt.Errorf("selector switch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("selector switch HTTP %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

// ProxyDelayMs tests the delay of a proxy node via Clash API.
// Returns latency in milliseconds, or -1 if unreachable.
func ProxyDelayMs(tag string, timeoutMs int) int {
	if timeoutMs == 0 {
		timeoutMs = 8000
	}

	encoded := url.PathEscape(tag)

	for _, testURL := range TestURLs {
		reqURL := fmt.Sprintf("%s/proxies/%s/delay?url=%s&timeout=%d",
			ClashAPI, encoded, url.QueryEscape(testURL), timeoutMs)

		resp, err := clashClient.Get(reqURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			var result struct {
				Delay int `json:"delay"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Delay > 0 {
				return result.Delay
			}
		}
	}
	return -1
}

// GetTraffic returns the current traffic stats from Clash API.
func GetTraffic() (map[string]interface{}, error) {
	resp, err := clashClient.Get(ClashAPI + "/traffic")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Traffic endpoint is streaming; read first line
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf[:n], &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetConnections returns current connections from Clash API.
func GetConnections() (map[string]interface{}, error) {
	resp, err := clashClient.Get(ClashAPI + "/connections")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// WriteConfig writes the sing-box config to disk.
func WriteConfig(configJSON []byte) error {
	tmp := ConfigPath + ".tmp"
	if err := os.WriteFile(tmp, configJSON, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return os.Rename(tmp, ConfigPath)
}

// Reload attempts to reload or restart sing-box.
// Tries service reload → restart → start → manual Popen.
func Reload() string {
	// Try service reload
	for _, svc := range []string{"sing-box", "sing-box-macflow"} {
		if err := exec.Command("service", svc, "reload").Run(); err == nil {
			return fmt.Sprintf("reloaded (%s)", svc)
		}
	}

	// Try service restart
	for _, svc := range []string{"sing-box", "sing-box-macflow"} {
		if err := exec.Command("service", svc, "restart").Run(); err == nil {
			return fmt.Sprintf("restarted (%s)", svc)
		}
	}

	// Try service start
	for _, svc := range []string{"sing-box", "sing-box-macflow"} {
		if err := exec.Command("service", svc, "start").Run(); err == nil {
			return fmt.Sprintf("started (%s)", svc)
		}
	}

	// Last resort: manual start
	sbPath, err := exec.LookPath("sing-box")
	if err != nil {
		return "sing-box not found"
	}

	cmd := exec.Command(sbPath, "run", "-c", ConfigPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Sprintf("manual start failed: %v", err)
	}
	// Detach the process
	go cmd.Wait()
	return "started (manual)"
}

// Stop stops all sing-box processes.
func Stop() string {
	for _, svc := range []string{"sing-box", "sing-box-macflow"} {
		exec.Command("service", svc, "stop").Run()
	}
	exec.Command("killall", "sing-box").Run()
	return "stopped"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
