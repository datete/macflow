package api

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"macflow/internal/netctl"
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
