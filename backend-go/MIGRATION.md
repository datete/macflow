# MACFlow Go 迁移路线图

## 状态：✅ 迁移完成 (v3.0.0)

Go 后端已全面取代 Python 守护进程并上线。以下为完整迁移结果。

## 最终指标

| 指标 | Python (旧) | Go (现) |
|------|-------------|---------|
| 二进制大小 | ~40MB (含依赖) | **8.8MB** (静态链接) |
| API 路由 | 47 条 | **47 条**（100% 兼容）|
| 测试覆盖 | Python 111 tests | Go 8 packages + 集成测试 |
| ARM64 构建 | pip install | **单文件 go build** |
| 版本管理 | 无 | **ldflags -X main.Version** |
| 并发模型 | GIL + asyncio | Goroutine + sync.RWMutex |

## 已完成阶段

### Phase 0 ✅ — 脚手架
- `cmd/macflowd/main.go`：入口 + 优雅退出 + 版本变量
- `internal/config/config.go`：环境变量配置（含 `Version` 字段）
- `internal/state/store.go`：线程安全状态存储
- `internal/auth/auth.go`：PBKDF2 认证 + 会话管理
- `internal/health/monitor.go`：并发健康检查

### Phase 1 ✅ — Auth & CRUD（全部 47 条路由）
- Auth：setup/login/logout/disable/status
- Settings + Toggle
- Sources CRUD（3x-UI 同步）
- Subscriptions CRUD
- Nodes CRUD（含批量、手动添加、链接导入）
- Devices CRUD（含批量、节点绑定、IP/备注管理）

### Phase 2 ✅ — 网络控制
- nftables 规则渲染 + 原子应用
- sing-box 配置生成
- IP 规则/路由管理
- `POST /api/apply`（热应用）+ `POST /api/rollback`

### Phase 3 ✅ — 健康 & 实时
- 节点探测：延迟/速度/出口 IP
- 系统健康检查（singbox/tun/nftables/dns/leak/ipv6）
- SSE 实时推送（`/api/events`）
- Alert 管理 + fail-close 守卫

### Phase 4 ✅ — 系统集成
- Traffic/Connections（代理 Clash API）
- System Info（`/api/system/info`，含 `version` 字段）
- OTA 更新（GitHub API）
- 日志（`/api/logs?q=` 全文搜索）
- DHCP 发现

### Phase 5 ✅ — 测试 & 部署
- 单元测试：auth/config/health/netctl/parsers/singbox/state
- 集成测试：`internal/api/api_handler_test.go` + `api_auth_test.go`
- ARM64 交叉编译 + ldflags 版本注入
- `openwrt/build-arm64-ipk.sh`：git tag → ldflags 自动化
- `openwrt/macflow/Makefile`：`PKG_VERSION` 动态 git tag

## 后续维护

Python `backend/` 保留做参考，不再作为主运行时。  
OpenWrt 打包使用 `backend-go/macflowd-arm64` 预编译二进制。



| 指标 | Python (当前) | Go (目标) |
|------|-------------|----------|
| 二进制大小 | ~40MB (含依赖) | ~5MB (静态链接) |
| 内存占用 | ~50-80MB | ~8-15MB |
| 启动时间 | ~3-5s | <200ms |
| 并发模型 | GIL + 线程池 | Goroutine |
| 网络控制 | subprocess 调用 | 直接 /proc + netlink |
| 部署 | Python + pip + venv | 单文件 COPY |

## 已完成：Phase 0 — 脚手架 ✅

```
backend-go/
├── go.mod                           # 模块定义
├── cmd/macflowd/main.go            # 入口 + 优雅退出
├── internal/
│   ├── config/config.go            # 环境变量配置
│   ├── state/store.go              # 线程安全状态存储 (RWMutex)
│   ├── auth/auth.go                # PBKDF2 认证 + session
│   ├── health/monitor.go           # goroutine 并发健康检查
│   ├── api/router.go               # 42 路由注册 + 3 中间件 + handleStatus
│   ├── netctl/netctl.go            # 网络控制 (直读 /proc)
│   └── parsers/parsers.go          # 协议链接解析器
```

关键设计改进：
- **直接读 /proc/net/arp** 代替 `subprocess.run(["ip", "neigh"])`
- **net.Interfaces()** 代替 `subprocess.run(["ip", "route"])`
- **sync.RWMutex** 代替 Python threading.RLock
- **context.Context** 贯穿所有 goroutine，支持优雅退出

## Phase 1 — Auth & CRUD（预计 11 天）

### 1.1 Auth 端点
- `POST /api/auth/setup` — 初始密码设置
- `POST /api/auth/login` — 登录 + 设置 cookie
- `POST /api/auth/logout` — 清除 session
- `POST /api/auth/disable` — 关闭认证
- `GET /api/auth/status` — 认证状态查询

### 1.2 Settings / Toggle
- `GET /api/settings` — 返回当前设置
- `PUT /api/settings` — 更新 default_policy / failure_policy / DNS
- `POST /api/service/toggle` — 启停服务

### 1.3 Sources CRUD
- `GET /api/sources` — 列表 3x-UI 源
- `POST /api/sources` — 创建源 (含 URL 验证)
- `PUT /api/sources/:sid` — 更新源
- `DELETE /api/sources/:sid` — 删除源
- `POST /api/sources/:sid/sync` — 从 3x-UI 面板同步节点

### 1.4 Subscriptions CRUD
- `GET /api/subscriptions`
- `POST /api/subscriptions` — 创建 (含 SSRF 防护)
- `PUT /api/subscriptions/:sid`
- `DELETE /api/subscriptions/:sid`
- `POST /api/subscriptions/:sid/sync`

### 1.5 Nodes CRUD
- `GET /api/nodes` — 列表 + 过滤
- `POST /api/nodes/manual` — 手动添加
- `POST /api/nodes/import-link/preview` — 导入预览
- `POST /api/nodes/import-link` — 导入确认
- `POST /api/nodes/sync-all` — 全量同步
- `PUT /api/nodes/:tag` — 更新节点
- `DELETE /api/nodes/:tag` — 删除
- `POST /api/nodes/batch` — 批量操作
- `PUT /api/nodes/:tag/toggle` — 启停

### 1.6 Devices CRUD
- `GET /api/devices`
- `POST /api/devices` — 创建/更新设备
- `POST /api/devices/batch` — 批量管理
- `PUT /api/devices/:mac/node` — 绑定节点
- `PUT /api/devices/:mac/remark` — 备注
- `PUT /api/devices/:mac/ip` — 固定 IP
- `DELETE /api/devices/:mac` — 删除

## Phase 2 — 网络控制（预计 9 天）

### 2.1 nftables 规则
- 从 `state.json` 渲染 nft 规则集
- 支持 whitelist / blacklist / global 策略
- 原子 apply (`nft -f`)

### 2.2 sing-box 配置生成
- 根据启用的节点生成 sing-box JSON 配置
- selector outbound 管理
- DNS 规则集成

### 2.3 IP 规则/路由
- `ip rule add fwmark` 管理
- 路由表管理
- tun 接口检测

### 2.4 Apply + Rollback
- `POST /api/apply` — 原子应用 (nft + singbox + ip rules)
- `POST /api/rollback` — 回滚到上一版本
- Policy version 管理

## Phase 3 — 健康 & 实时（预计 8 天）

### 3.1 节点探测
- goroutine pool 并发探测延迟
- TCP/HTTP 连通性测试
- 速度测试 (下载测速)
- health score 计算

### 3.2 系统健康检查
- singbox 进程检查
- tun 接口检查  
- nftables 规则检查
- dns_guard 检查
- leak_guard 检查
- ipv6_guard 检查

### 3.3 SSE 实时推送
- `/api/events` — 流量数据 (2s) + 系统信息 (10s)
- gin `c.Stream()` / `c.SSEvent()`

### 3.4 Egress 检测
- 并发请求多个 IP 检测服务
- GeoIP 查询
- 缓存结果

### 3.5 Alert 管理
- fail-close 守卫
- auto-heal 机制
- alert 确认

## Phase 4 — 系统集成（预计 5 天）

- Traffic/Connections — 代理 sing-box Clash API
- System Info — 直读 /proc/meminfo, /proc/loadavg, /proc/uptime
- OTA 更新 — GitHub API 检查 + 下载
- Logs — 读取 audit log 文件
- DHCP Discover — 读 /tmp/dhcp.leases
- Captive Portal — 状态检测

## Phase 5 — 测试 & 部署（预计 8 天）

### 5.1 测试
- 单元测试 (state, auth, parsers, health)
- HTTP handler 集成测试 (httptest)
- mock 网络操作

### 5.2 构建 & 部署
```bash
# 交叉编译
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o macflowd ./cmd/macflowd

# IPK 打包
# 修改 openwrt/macflow/Makefile 从 Go 编译
```

### 5.3 迁移切换
1. 先并行运行 Python + Go（不同端口）对比响应
2. 前端切换到 Go 端口
3. 移除 Python 后端
4. 更新 Dockerfile

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| state.json 格式不兼容 | 升级失败 | Go 使用相同 JSON 结构，已验证 |
| nftables 行为差异 | 网络中断 | 复用现有 .nft 模板，diff 验证 |
| sing-box API 变更 | 配置失败 | 锁定 sing-box 版本 |
| 前端 API 不兼容 | 界面异常 | Phase 1 后即可并行测试 |
