# MACFlow 项目联动、VM 流程与规划

## 一、项目整体联动关系

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  用户 / 管理员                                                                │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │ 浏览器 / API / SSE
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Web 前端 (web/index.html)                                                    │
│  - 仪表盘 / 节点管理 / 设备分流 / 访问控制 / 运行日志                           │
│  - SSE 实时推送（流量/连接/状态/系统信息）                                     │
│  - 登录认证（会话令牌 / Cookie / Bearer）                                     │
│  - 命令面板（Ctrl+K）/ 7 主题 / 移动端底部导航                                │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │ HTTP (REST API) + SSE
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Backend (backend/main.py)  :18080                                           │
│  - 51+ API 端点 + 认证中间件 + SSE 流                                        │
│  - 状态读写 data/state.json                                                   │
│  - 认证配置 data/auth.json（SHA-256 + 盐 + 会话）                             │
│  - 策略应用 → nftables + sing-box + ip rules                                  │
│  - 劫持中间件 → 未纳管设备访问 /captive                                       │
│  - IP 限频（5次/分钟，锁定 5 分钟）                                           │
└───┬─────────────────┬─────────────────┬─────────────────┬───────────────────┘
    │                 │                 │                 │
    ▼                 ▼                 ▼                 ▼
┌─────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────────┐
│nftables │   │ sing-box    │   │ ip rule     │   │ DHCP / ARP      │
│macflow  │   │ config.json │   │ fwmark→表   │   │ (设备发现)       │
│原子应用 │   │ TUN+代理    │   │ table 100+  │   │ 含 ARP 回退     │
└─────────┘   └─────────────┘   └─────────────┘   └─────────────────┘
```

### 关键数据流

1. **设备分流**：MAC → nftables mark → ip rule 查表 → singtun0 → sing-box 按 source_ip 分流
2. **认证流**：请求 → 中间件检查 Token/Cookie → 公开路径放行 / 401 拒绝
3. **SSE 推送**：后端 asyncio 定时广播 → 前端 EventSource 接收 → 断开自动重连
4. **劫持流**：未纳管 HTTP → nftables redirect → 中间件 302 → captive.html

---

## 二、VM 与项目的联动方式

### 2.1 三种运行环境

| 环境 | 用途 | 入口 |
|------|------|------|
| **Docker** | 本地开发/演示，无真实分流 | `docker compose up` → http://localhost:18080 |
| **WSL + netns** | 无 VM，脚本级测试（render + atomic_apply + smoke） | `scripts/setup-netns.sh` + `core/apply/atomic_apply.sh` |
| **QEMU VM (iStoreOS)** | 完整环境：面板 + nftables + sing-box + 劫持 | `vm/run-istoreos.sh`（在 WSL 内执行） |

### 2.2 VM 端口与转发

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Windows 本机                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ 可选: vm/win-proxy.py 或 vm/macflow-proxy.py                         │ │
│  │ 监听 :18080 → 调 WSL curl → 转发到 127.0.0.1:18080                    │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │ localhost / 127.0.0.1
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  WSL (Ubuntu 等)                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  QEMU 进程 (vm/run-istoreos.sh)                                      │ │
│  │  hostfwd: 2222→VM:22, 8080→VM:80, 18080→VM:18080                    │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  Windows 访问:  localhost:2222 = VM SSH                                   │
│                 localhost:8080 = VM LuCI (iStoreOS 管理)                  │
│                 localhost:18080 = VM 内 macflowd 面板                     │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │ 端口转发进 VM
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  iStoreOS VM (QEMU 内)                                                   │
│  - SSH :22 → 需通过 vm/fix-ssh.exp 或串口配置 WAN 访问                   │
│  - LuCI :80                                                              │
│  - macflowd :18080 (backend + 静态页)                                     │
│  - sing-box :9090 (Clash API) / TUN singtun0                             │
└──────────────────────────────────────────────────────────────────────────┘
```

- **VM 内**：面板 18080、LuCI 80、SSH 22、Clash API 9090 等都在 VM 里监听；QEMU 的 `hostfwd` 把宿主机的 2222/8080/18080 转到 VM 的 22/80/18080。
- **Windows 直接访问**：浏览器打开 `http://localhost:18080` 即可访问 VM 里的面板（无需 win-proxy，因端口已转发）。
- **win-proxy / macflow-proxy**：当 18080 只在 WSL 的 localhost 上、Windows 无法直接访问时，在 Windows 起代理，用 WSL 里的 curl 转发到 `http://127.0.0.1:18080`。

### 2.3 VM 相关脚本职责

| 脚本 | 作用 |
|------|------|
| `vm/run-istoreos.sh` | 在 WSL 内启动 QEMU iStoreOS，端口 2222/8080/18080 转发 |
| `vm/setup-vm-deps.sh` | VM 内安装 Python/nft 等依赖（需先拷贝进 VM 或 SSH 执行） |
| `vm/deploy-panel.sh` | VM 内部署 core/config/scripts，注册 procd 服务 |
| `vm/start-panel.sh` | VM 内拷贝 backend+web，写 init 脚本，前台起 uvicorn 验证 |
| `vm/install-singbox.sh` | VM 内安装 sing-box |
| `vm/fix-ssh.exp` | 串口/expect 修 VM 内 SSH（dropbear 监听、防火墙） |
| `vm/final-check.sh` | VM 内一键检查：sing-box/TUN/nftables/DNS/Leak/路由/面板/Clash API |
| `vm/test-apply.sh` | VM 内通过 API 加节点+设备、apply，并检查 nft/ip/sing-box |
| `vm/test-splitting.sh` | 分流验证：多节点多设备、mac_to_mark、route 规则、ip rule |
| `vm/test-whitelist.sh` | 白名单/fail-close/fail-open/block 策略与禁用开关 |
| `vm/test-stability.sh` | 重启、连续 apply、加删节点、切换节点 |
| `vm/test-concurrency.sh` | 并发设备、set_node、apply 竞态、多 Agent |
| `vm/run-all-tests.sh` | 顺序跑上述测试 + final-check |
| `vm/quick-connect.sh` | 跨网络快速发现入口（MACFlow/LuCI/SSH），支持固定域名优先与 WSL SSH 回退 |
| `vm/sync-connect-from-tailscale.sh` | 从 VM 的 tailscale 状态自动同步 tailnet 域名到本机 connect.env |
| `vm/macflow-proxy.py` | Windows 上 HTTP 代理，转发到 WSL 的 127.0.0.1:18080 |
| `vm/win-proxy.py` | Windows 上统一代理，/api → 18080，/luci → 8080 |

---

## 三、从零到 VM 的推荐流程

### 3.1 准备（一次性）

1. **WSL 内**：安装 QEMU、OVMF、expect（串口修 SSH 用）。
2. **镜像**：`vm/istoreos.img` 放到 `vm/`，首次运行会生成 `vm/istoreos-work.qcow2`。
3. **启动 VM**（在 WSL 里）：
   ```bash
   cd /mnt/c/Users/datet/Desktop/插件开发/vm
   bash run-istoreos.sh
   ```
4. **等系统起来**：可用 `vm/wait-boot.sh` 轮询 http://localhost:8080，或手动等约 1 分钟。
5. **修 SSH（可选）**：若需从 WSL/Windows SSH 进 VM，在 WSL 内执行：
   ```bash
   expect vm/fix-ssh.exp
   ```
   之后可从 Windows 用 `ssh -p 2222 root@localhost`（或通过 WSL 的 localhost）。

### 3.2 部署面板到 VM

- **若已能 SSH 进 VM**：
  ```bash
  scp -P 2222 -r backend web root@localhost:/tmp/macflow/
  ssh -p 2222 root@localhost 'bash -s' < vm/start-panel.sh
  ```
  或把 `backend`、`web` 拷到 VM 的 `/tmp/macflow/` 后，在 VM 内执行 `vm/start-panel.sh`。
- **若暂时无 SSH**：可通过串口（telnet 127.0.0.1 4445）在 VM 内建目录、拷文件（或使用之前实现的 HTTP/NC 部署方式）。

### 3.3 安装 sing-box（VM 内）

在 VM 内执行 `vm/install-singbox.sh`（或按脚本逻辑安装 sing-box 并配置 TUN）。

### 3.4 日常调试

1. **只开面板**：确保 VM 已启，浏览器访问 http://localhost:18080（端口已在 QEMU 转发）。
2. **在 VM 内跑测试**（SSH 进 VM 后）：
   ```bash
   cd /opt/macflow && bash vm/run-all-tests.sh
   ```
3. **在 Windows 上看 VM 面板**：同上，http://localhost:18080；若 18080 只监听在 WSL，可先起 `vm/macflow-proxy.py` 再访问 Windows 上代理端口。

---

## 四、数据与策略流程（与 VM 无关的通用逻辑）

1. **配置来源**：`data/state.json`（节点、设备、策略、DNS、enabled、default_policy、failure_policy）。
2. **应用链路**：  
   `POST /api/apply` → 读 state → `_build_singbox_full()` 写 sing-box 配置 → `_apply_nftables()` 刷 macflow 表（含劫持链）→ 重启/reload sing-box → `_apply_ip_rules()` 写 fwmark 规则与路由表。
3. **设备分流**：  
   MAC → nftables `mac_to_mark` → 打 mark → ip rule 按 fwmark 查表 → 表 100+ 默认走 singtun0 → sing-box 按 `source_ip_cidr` 将设备 IP 绑到对应节点或 direct-out。
4. **劫持**：  
   未纳管设备 HTTP 访问被 nftables `captive_redirect` 重定向到 :18080，中间件再 302 到 `/captive?ip=...`，captive.html 展示 MAC/IP 与面板链接。

---

## 五、规划与阶段

| 阶段 | 内容 | 状态 |
|------|------|------|
| A | 本地调试基线（WSL/netns）、MAC 分流、事务化应用、DNS 防泄露 | ✅ 完成 |
| B | 3x-ui 同步、selector、Web 面板、设备级分流、白名单/fail-close | ✅ 完成 |
| B+ | API 认证（SHA-256+会话+限频）、SSE 实时推送、UI 响应式优化 | ✅ 完成 |
| VM 测试 | final-check、test-apply、分流/白名单/稳定性/并发测试脚本 | ✅ 已编写 |
| 固件化 | R2S/R4S/R5S/H68K 等 ARM64 固件打包 | 🔲 后续 |

### B+ 阶段新增功能清单

**后端（backend/main.py）**：

- nftables 原子应用（flush+delete+create 单次 `nft -f -`）
- 回滚后重新应用 `_reconcile_runtime` + `_apply_lock`
- DNS 防泄露修复（`"final": default_dns_tag`）
- TLS 不安全连接可配置（`tls.insecure`）
- br-lan 自动检测（`_detect_lan_iface()`，支持 eth0/br-lan/br0）
- DHCP 数据回退至 ARP 表
- 劫持链使用自动检测的 LAN 接口
- 路由表顺序分配（`_mark_to_table()` 映射表 100+）
- API 认证中间件 + 6 个认证端点
- IP 限频（5次/分钟，超限锁定 5 分钟）
- 会话管理（7 天 TTL，最多 50 会话）
- 认证配置 mtime 缓存
- SSE 实时事件流（traffic/connections/status/sysinfo）
- 探测循环脏标记优化（`_need_apply`）
- 安全重启（PID 级，非 killall）
- CORS 限制（`MACFLOW_CORS_ORIGINS` 环境变量）

**前端（web/index.html）**：

- 全局加载条 + 骨架微光动画
- 移动端底部导航栏（5 个 SVG 图标标签页）
- 滚动返回顶部按钮
- 登录对话框 + 认证徽章
- SSE EventSource 客户端 + 断线自动重连 + 轮询降级
- focus-visible 无障碍焦点环
- 卡片悬停、按钮加载态、表格行悬停
- 状态指示灯脉动动画
- 7 主题 / 3 字体 / 3 密度
- 命令面板（Ctrl+K）
- Canvas 网络拓扑图

当前代码已具备：设备对应分类（node_tag + source_ip 路由）、无冗余逻辑、rollback/apply 加锁、ip rule 只清 20000–29999、set_node 后 sing-box 热加载、未纳管设备劫持页与 nftables 劫持链、API 认证、实时事件推送。
