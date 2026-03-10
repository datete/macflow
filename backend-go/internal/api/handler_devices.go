package api

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"

	"macflow/internal/state"
)

var macRegexp = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$`)

// normalizeMac converts a MAC address to uppercase colon-separated format.
func normalizeMac(mac string) string {
	mac = strings.ToUpper(strings.TrimSpace(mac))
	mac = strings.ReplaceAll(mac, "-", ":")
	return mac
}

// GET /api/devices
func (s *Server) handleDevices(c *gin.Context) {
	st := s.store.Read()

	// Build node lookup
	nodeMap := make(map[string]state.Node, len(st.Nodes))
	for _, n := range st.Nodes {
		nodeMap[n.Tag] = n
	}

	result := make([]gin.H, 0, len(st.Devices))
	for _, d := range st.Devices {
		item := gin.H{
			"name":     d.Name,
			"mac":      d.MAC,
			"node_tag": d.NodeTag,
			"managed":  d.Managed,
			"mark":     d.Mark,
			"remark":   d.Remark,
			"ip":       d.IP,
			"last_ip":  d.LastIP,
		}

		// Attach node detail if bound
		if n, ok := nodeMap[d.NodeTag]; ok {
			item["node_detail"] = gin.H{
				"tag":    n.Tag,
				"type":   n.Type,
				"server": n.Server,
			}
		}

		result = append(result, item)
	}

	c.JSON(200, result)
}

// POST /api/devices (upsert)
func (s *Server) handleDeviceUpsert(c *gin.Context) {
	var req struct {
		Name    string `json:"name" binding:"required,max=256"`
		MAC     string `json:"mac" binding:"required"`
		NodeTag string `json:"node_tag,omitempty"`
		Managed *bool  `json:"managed,omitempty"`
		Remark  string `json:"remark,omitempty"`
		IP      string `json:"ip,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误: " + err.Error()})
		return
	}

	req.MAC = normalizeMac(req.MAC)
	if !macRegexp.MatchString(req.MAC) {
		c.JSON(400, gin.H{"detail": fmt.Sprintf("无效的 MAC 地址: %s", req.MAC)})
		return
	}

	if req.IP != "" {
		if net.ParseIP(req.IP) == nil {
			c.JSON(400, gin.H{"detail": fmt.Sprintf("无效的 IP 地址: %s", req.IP)})
			return
		}
	}

	if req.NodeTag == "" {
		req.NodeTag = "direct"
	}

	managed := true
	if req.Managed != nil {
		managed = *req.Managed
	}

	if err := s.store.Update(func(st *state.State) {
		// Find existing device by MAC
		for i := range st.Devices {
			if st.Devices[i].MAC == req.MAC {
				// Update
				st.Devices[i].Name = req.Name
				st.Devices[i].NodeTag = req.NodeTag
				st.Devices[i].Managed = managed
				if req.Remark != "" {
					st.Devices[i].Remark = req.Remark
				}
				if req.IP != "" {
					st.Devices[i].IP = req.IP
				}
				return
			}
		}

		// Create new
		mark := s.store.NextMark()
		st.Devices = append(st.Devices, state.Device{
			Name:    req.Name,
			MAC:     req.MAC,
			NodeTag: req.NodeTag,
			Managed: managed,
			Remark:  req.Remark,
			IP:      req.IP,
			Mark:    mark,
		})
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("device_upsert", fmt.Sprintf("mac=%s name=%s", req.MAC, req.Name))
	c.JSON(200, gin.H{"ok": true, "runtime": runtime})
}

// POST /api/devices/batch
func (s *Server) handleDeviceBatch(c *gin.Context) {
	var req struct {
		Devices []struct {
			Name    string `json:"name" binding:"required,max=256"`
			MAC     string `json:"mac" binding:"required"`
			NodeTag string `json:"node_tag,omitempty"`
			Managed *bool  `json:"managed,omitempty"`
			Remark  string `json:"remark,omitempty"`
			IP      string `json:"ip,omitempty"`
		} `json:"devices" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	count := 0
	if err := s.store.Update(func(st *state.State) {
		macIdx := make(map[string]int, len(st.Devices))
		for i, d := range st.Devices {
			macIdx[d.MAC] = i
		}

		for _, d := range req.Devices {
			mac := normalizeMac(d.MAC)
			if !macRegexp.MatchString(mac) {
				continue
			}
			nodeTag := d.NodeTag
			if nodeTag == "" {
				nodeTag = "direct"
			}
			managed := true
			if d.Managed != nil {
				managed = *d.Managed
			}

			if idx, ok := macIdx[mac]; ok {
				// Update
				st.Devices[idx].Name = d.Name
				st.Devices[idx].NodeTag = nodeTag
				st.Devices[idx].Managed = managed
				if d.Remark != "" {
					st.Devices[idx].Remark = d.Remark
				}
				if d.IP != "" {
					st.Devices[idx].IP = d.IP
				}
			} else {
				// Create
				mark := s.store.NextMark()
				st.Devices = append(st.Devices, state.Device{
					Name:    d.Name,
					MAC:     mac,
					NodeTag: nodeTag,
					Managed: managed,
					Remark:  d.Remark,
					IP:      d.IP,
					Mark:    mark,
				})
				macIdx[mac] = len(st.Devices) - 1
			}
			count++
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("device_batch", fmt.Sprintf("count=%d", count))
	c.JSON(200, gin.H{"ok": true, "count": count, "runtime": runtime})
}

// PUT /api/devices/:mac/node
func (s *Server) handleDeviceSetNode(c *gin.Context) {
	mac := normalizeMac(c.Param("mac"))
	var req struct {
		NodeTag string `json:"node_tag" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	// Validate node exists (unless "direct")
	if req.NodeTag != "direct" {
		st := s.store.Read()
		nodeExists := false
		for _, n := range st.Nodes {
			if n.Tag == req.NodeTag {
				nodeExists = true
				break
			}
		}
		if !nodeExists {
			c.JSON(400, gin.H{"detail": fmt.Sprintf("节点 '%s' 不存在", req.NodeTag)})
			return
		}
	}

	found := false
	if err := s.store.Update(func(st *state.State) {
		for i := range st.Devices {
			if st.Devices[i].MAC == mac {
				found = true
				st.Devices[i].NodeTag = req.NodeTag
				st.Devices[i].Managed = true
				if st.Devices[i].Mark == 0 {
					st.Devices[i].Mark = s.store.NextMark()
				}
				break
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	if !found {
		c.JSON(404, gin.H{"detail": "设备不存在"})
		return
	}

	runtime := s.rt.HotApply(false)
	c.JSON(200, gin.H{"ok": true, "mac": mac, "node_tag": req.NodeTag, "applied": true, "runtime": runtime})
}

// PUT /api/devices/:mac/remark
func (s *Server) handleDeviceRemark(c *gin.Context) {
	mac := normalizeMac(c.Param("mac"))
	var req struct {
		Remark string `json:"remark" binding:"max=1024"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	found := false
	if err := s.store.Update(func(st *state.State) {
		for i := range st.Devices {
			if st.Devices[i].MAC == mac {
				found = true
				st.Devices[i].Remark = req.Remark
				break
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	if !found {
		c.JSON(404, gin.H{"detail": "设备不存在"})
		return
	}

	s.audit.Log("device_remark", fmt.Sprintf("mac=%s", mac))
	c.JSON(200, gin.H{"ok": true})
}

// PUT /api/devices/:mac/ip
func (s *Server) handleDeviceIP(c *gin.Context) {
	mac := normalizeMac(c.Param("mac"))
	var req struct {
		IP string `json:"ip,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	if req.IP != "" && net.ParseIP(req.IP) == nil {
		c.JSON(400, gin.H{"detail": fmt.Sprintf("无效的 IP: %s", req.IP)})
		return
	}

	// Pre-check IP conflict and device existence
	st := s.store.Read()
	deviceExists := false
	for _, d := range st.Devices {
		if d.MAC == mac {
			deviceExists = true
		}
		if req.IP != "" && d.MAC != mac && d.IP == req.IP {
			c.JSON(409, gin.H{"detail": fmt.Sprintf("IP %s 已分配给设备 %s", req.IP, d.Name)})
			return
		}
	}
	if !deviceExists {
		c.JSON(404, gin.H{"detail": "设备不存在"})
		return
	}

	if err := s.store.Update(func(st *state.State) {
		for i := range st.Devices {
			if st.Devices[i].MAC == mac {
				st.Devices[i].IP = req.IP
				break
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	runtime := s.rt.HotApply(false)
	c.JSON(200, gin.H{"ok": true, "mac": mac, "ip": req.IP, "runtime": runtime})
}

// DELETE /api/devices/:mac
func (s *Server) handleDeviceDelete(c *gin.Context) {
	mac := normalizeMac(c.Param("mac"))

	deleted := 0
	if err := s.store.Update(func(st *state.State) {
		newDevices := make([]state.Device, 0, len(st.Devices))
		for _, d := range st.Devices {
			if d.MAC == mac {
				deleted++
			} else {
				newDevices = append(newDevices, d)
			}
		}
		st.Devices = newDevices
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("device_delete", mac)
	c.JSON(200, gin.H{"ok": true, "deleted": deleted, "runtime": runtime})
}
