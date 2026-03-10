package api

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/netctl"
	"macflow/internal/state"
)

// handleDHCPDiscover discovers DHCP clients from leases and ARP table.
//
// GET /api/dhcp/discover
func (s *Server) handleDHCPDiscover(c *gin.Context) {
	type dhcpEntry struct {
		MAC        string  `json:"mac"`
		IP         string  `json:"ip"`
		Hostname   string  `json:"hostname"`
		Managed    bool    `json:"managed"`
		NodeTag    *string `json:"node_tag"`
		DeviceName *string `json:"device_name"`
	}

	// Collect DHCP leases (dedup by MAC)
	seen := map[string]*dhcpEntry{} // uppercase MAC -> entry

	// dnsmasq lease files
	for _, leaseFile := range []string{"/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases"} {
		data, err := os.ReadFile(leaseFile)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			mac := strings.ToUpper(fields[1])
			ip := fields[2]
			hostname := fields[3]
			if hostname == "*" {
				hostname = ""
			}
			if _, ok := seen[mac]; !ok {
				seen[mac] = &dhcpEntry{MAC: mac, IP: ip, Hostname: hostname}
			}
		}
	}

	// odhcpd files
	odhcpdDir := "/tmp/hosts/odhcpd"
	entries, err := os.ReadDir(odhcpdDir)
	if err == nil {
		for _, entry := range entries {
			data, err := os.ReadFile(odhcpdDir + "/" + entry.Name())
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				ip := fields[0]
				mac := strings.ToUpper(fields[1])
				hostname := ""
				if len(fields) >= 3 {
					hostname = fields[2]
				}
				if _, ok := seen[mac]; !ok {
					seen[mac] = &dhcpEntry{MAC: mac, IP: ip, Hostname: hostname}
				}
			}
		}
	}

	// Supplement with ARP table
	arpMap := netctl.ResolveMACToIP()
	for mac, ip := range arpMap {
		macUpper := strings.ToUpper(mac)
		if _, ok := seen[macUpper]; !ok {
			seen[macUpper] = &dhcpEntry{MAC: macUpper, IP: ip}
		}
	}

	// Cross-reference with state
	st := s.store.Read()
	deviceMap := map[string]int{} // uppercase MAC -> index in Devices
	for i, d := range st.Devices {
		deviceMap[strings.ToUpper(d.MAC)] = i
	}

	var result []dhcpEntry
	for _, entry := range seen {
		if idx, ok := deviceMap[entry.MAC]; ok {
			d := st.Devices[idx]
			entry.Managed = d.Managed
			tag := d.NodeTag
			entry.NodeTag = &tag
			name := d.Name
			entry.DeviceName = &name
		}
		result = append(result, *entry)
	}

	if result == nil {
		result = []dhcpEntry{}
	}

	c.JSON(http.StatusOK, result)
}

// handleDHCPLeases returns static DHCP bindings from state.
//
// GET /api/dhcp/leases
func (s *Server) handleDHCPLeases(c *gin.Context) {
	st := s.store.Read()
	if st.DHCPBindings == nil {
		c.JSON(http.StatusOK, []state.DHCPBinding{})
		return
	}
	c.JSON(http.StatusOK, st.DHCPBindings)
}

// handleDHCPBind creates or updates a static DHCP binding.
//
// POST /api/dhcp/bind
// Body: {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.100", "hostname": "mypc", "remark": ""}
func (s *Server) handleDHCPBind(c *gin.Context) {
	var req struct {
		MAC      string `json:"mac" binding:"required"`
		IP       string `json:"ip" binding:"required"`
		Hostname string `json:"hostname"`
		Remark   string `json:"remark"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "请求格式错误"})
		return
	}

	req.MAC = strings.ToUpper(strings.TrimSpace(req.MAC))
	req.IP = strings.TrimSpace(req.IP)
	if req.MAC == "" || req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "MAC 和 IP 不能为空"})
		return
	}

	var updated bool
	err := s.store.Update(func(st *state.State) {
		for i, b := range st.DHCPBindings {
			if strings.ToUpper(b.MAC) == req.MAC {
				st.DHCPBindings[i].IP = req.IP
				st.DHCPBindings[i].Hostname = req.Hostname
				st.DHCPBindings[i].Remark = req.Remark
				updated = true
				return
			}
		}
		st.DHCPBindings = append(st.DHCPBindings, state.DHCPBinding{
			MAC:      req.MAC,
			IP:       req.IP,
			Hostname: req.Hostname,
			Remark:   req.Remark,
			Created:  time.Now().Unix(),
		})
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "保存失败"})
		return
	}

	// Write dnsmasq static-hosts file
	writeDHCPHostsFile(s)

	msg := "绑定已创建"
	if updated {
		msg = "绑定已更新"
	}
	s.audit.Log("dhcp_bind", req.MAC+"→"+req.IP)
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": msg})
}

// handleDHCPBindDelete removes a static DHCP binding.
//
// DELETE /api/dhcp/bind/:mac
func (s *Server) handleDHCPBindDelete(c *gin.Context) {
	mac := strings.ToUpper(c.Param("mac"))

	var found bool
	err := s.store.Update(func(st *state.State) {
		for i, b := range st.DHCPBindings {
			if strings.ToUpper(b.MAC) == mac {
				st.DHCPBindings = append(st.DHCPBindings[:i], st.DHCPBindings[i+1:]...)
				found = true
				return
			}
		}
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "保存失败"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"detail": "绑定不存在"})
		return
	}

	writeDHCPHostsFile(s)
	s.audit.Log("dhcp_unbind", mac)
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "绑定已删除"})
}

// writeDHCPHostsFile writes /tmp/hosts/macflow-dhcp for dnsmasq.
func writeDHCPHostsFile(s *Server) {
	st := s.store.Read()
	var lines []string
	for _, b := range st.DHCPBindings {
		mac := strings.ToLower(b.MAC)
		parts := []string{mac, b.IP}
		if b.Hostname != "" {
			parts = append(parts, b.Hostname)
		}
		lines = append(lines, strings.Join(parts, ","))
	}
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	hostsDir := "/tmp/hosts"
	os.MkdirAll(hostsDir, 0o755)
	os.WriteFile(hostsDir+"/macflow-dhcp", []byte(content), 0o644)
}
