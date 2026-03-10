# MACFlow 变更日志

## v3.0.0 — 2025-07-03

### 后端重写 (backend-go/)

#### Go 重写
- **语言切换**：核心守护进程从 Python 重写为 Go（gin-gonic），内存/CPU 开销大幅降低
- **并发安全**：所有状态操作通过 `sync.RWMutex` 保护，消除 Python asyncio 竞态
- **47 条 API 路由**：完全兼容原 Python 后端路由集合
- **二进制分发**：预编译 `macflowd-arm64`（linux/arm64，约 8.8 MB，无运行时依赖）

#### 版本管理
- **ldflags 版本注入**：`var Version = "dev"`，通过 `-X main.Version=${GIT_TAG}` 在构建时注入
- **API 暴露**：`/api/health` 和 `/api/system/info` 响应均包含 `"version"` 字段
- **动态 PKG_VERSION**：`openwrt/macflow/Makefile` 改为 `shell git describe --tags` 动态获取

#### ARM64 构建优化
- `openwrt/build-arm64-ipk.sh`：自动读取 git tag 并注入 ldflags，无 tag 时 fallback 到 commit hash
- `openwrt/macflow/Makefile`：`PKG_VERSION` 从静态 `3.0.0` 改为 `$(shell git describe ...)`

#### 日志全文搜索
- **`?q=` 参数**：`GET /api/logs?q=keyword` 在 `message/event/component/details` 四字段中搜索（大小写不敏感）

### 测试覆盖

#### Go 集成测试（新增）
- `internal/api/testhelper_test.go`：`mockRuntime`、`newTestEnv()`、`do()` 共用助手
- `internal/api/api_handler_test.go`：10 个 handler 集成测试（status/health/system/nodes/devices/logs/settings/auth/egress）
- `internal/api/api_auth_test.go`：8 个 auth 集成测试（setup/login/logout/token 鉴权流程）
- **全量通过**：8 个 Go 包 100% 绿灯

#### Python 测试（维护）
- **111/111 通过**：auth、models、parsers、utils 全套 pytest 测试持续绿灯

### 前端 (web/index.html) — 4793 行

#### 新功能
- **自定义后端地址**：设置页"开发者选项"，`localStorage.macflow.backendUrl` 持久化，支持 URL 格式校验
- **节点日志搜索**：系统日志 `?q=` 搜索实时同步到后端搜索参数
- **节点排序箭头**：`.sorted-asc`/`.sorted-desc` 类，点击列表头显示排序方向
- **协议分布徽章**：节点统计栏增加协议类型分布迷你徽章（Top 6 按数量排序）
- **暗/亮主题切换**：顶栏 🌙/☀️ 按钮，`toggleDarkLight()` 单键循环切换
- **设备行为日志**：设备操作抽屉底部展示最近 10 条相关日志

#### 输入验证加固
- `setBackendUrl()`：`new URL()` 校验格式，非 http/https 协议拒绝保存
- `saveSettings()`：DNS 端口范围校验（1–65535），非法时自动聚焦提示，防重复点击
- `addManualNode()`：服务器地址不允许空格/斜杠，端口范围校验（1–65535）
- `applyDev()` / `quickManage()`：`dataset.busy` 防止并发重复请求

#### 错误防护
- `renderNodes()` / `renderDevices()`：外层 try-catch 错误边界，异常时显示友好提示行而非空白页

#### UI/UX 改进
- **空状态强化**：节点/设备空状态显示图标 + 引导操作按钮（"添加节点"/"刷新设备"）
- **Toast 升级**：新增 `warn` 黄色类型；错误 4s/警告 3.5s 自动延长；右上角 ✕ 手动关闭；堆叠上限 8 条
- **节点表右键菜单**：延迟测试 / 速度测试 / 出口 IP / 编辑 / 启用-禁用 / 复制标签 / 删除
- **设备表右键菜单**：打开操作面板 / 复制 MAC / 复制 IP / 纳管 / 移除设备
- **右键菜单 CSS**：`.ctx-menu` / `.ctx-item` / `.ctx-item.danger` 统一动画样式

---

## v2.0.0 — 2025-06-26

### 后端 (backend/main.py)

#### 安全与认证
- **API 认证系统**：SHA-256 + 随机盐密码哈希，会话令牌（7 天 TTL，最多 50 会话）
- **IP 限频**：每 IP 每分钟最多 5 次登录尝试，超限锁定 5 分钟
- **认证中间件**：自动拦截非公开路径，支持 `X-Auth-Token` / Cookie / Bearer 三种令牌传递
- **认证配置缓存**：文件 mtime 检查避免频繁磁盘 IO
- **CORS 限制**：支持 `MACFLOW_CORS_ORIGINS` 环境变量限制允许的源
- **安全重启**：更新后使用 PID 级重启（`os.getpid()`），不再 `killall python3`

#### 实时推送
- **SSE 事件流**：`/api/events` 端点，使用 `StreamingResponse` + `asyncio.Queue`
- **四类事件**：`traffic`（2s）、`connections`（2s）、`status`（2s）、`sysinfo`（10s）
- **认证感知**：SSE 端点支持 query param / header / cookie 传递令牌
- **心跳保活**：每 30 秒发送 keepalive 注释

#### 核心修复
- **nftables 原子应用**：flush + delete + create 在单次 `nft -f -` 中完成，消除中间状态
- **回滚修复**：回滚后重新应用 `_reconcile_runtime` 并使用 `_apply_lock` 防止并发
- **DNS 防泄露**：sing-box DNS 配置添加 `"final": default_dns_tag` 防止泄露
- **TLS 可配置**：`tls.insecure` 字段控制节点 TLS 证书验证
- **LAN 接口自动检测**：`_detect_lan_iface()` 支持 br-lan / eth0 / br0 等不同固件
- **ARP 回退**：DHCP 设备发现失败时自动回退到 ARP 表
- **劫持链修复**：使用自动检测的 LAN 接口名而非硬编码
- **路由表顺序分配**：`_mark_to_table()` 按策略 mark 顺序映射表 100+
- **探测循环优化**：脏标记 `_need_apply`，每周期只做一次 `_runtime_hot_apply`
- **死代码清理**：移除冗余 `import os` 和无用 `deleted` 变量

### 前端 (web/index.html)

#### UI 优化
- **全局加载条**：API 请求期间顶部彩色进度条动画
- **骨架屏加载**：shimmer 微光动画占位符
- **移动端底部导航**：5 个 SVG 图标标签页（< 960px 显示）
- **滚动返回顶部**：浮动按钮（滚动 > 300px 显示）
- **卡片悬停效果**：边框高亮 + 阴影提升
- **按钮加载态**：`.loading` class 添加旋转 spinner
- **表格行悬停**：柔和背景色变化
- **状态指示灯脉动**：`.on` 状态绿色脉动动画
- **focus-visible 焦点环**：无障碍键盘导航支持
- **徽章微交互**：悬停缩放效果
- **空状态插图**：数据为空时的友好提示

#### 认证 UI
- **登录对话框**：全屏遮罩 + 居中登录卡片 + 密码输入
- **认证徽章**：仪表盘显示当前认证状态
- **令牌管理**：localStorage 持久化 + 自动附加请求头
- **401 自动处理**：Token 失效自动弹出登录框

#### 实时推送
- **SSE 客户端**：EventSource 接收 traffic/connections/status/sysinfo 事件
- **自动重连**：指数退避重连（1s → 2s → 4s → ... → 30s）
- **轮询降级**：SSE 断开时自动回退到 setInterval 轮询（3s/30s）

### 劫持页 (web/captive.html)

- 轮询进度条（CSS 动画 + JS 同步）
- 英雄图标浮动动画
- 授权成功 ✓ 动画
- focus-visible 无障碍焦点环
- 按钮悬停/激活/加载态

### 配置与构建

- `config/policy.example.json`：mark 值改为 256/257，table 改为 100/101
- `build/iprules.sh`：mark 0x100/0x101，table 100/101
- `build/macflow.nft`：mark 0x100/0x101
- `core/rule-engine/render_policy.py`：添加 `render_iprules()` 文档字符串

### 文档

- `README.md`：重写为 v2.0 格式，新增认证、SSE、环境变量、前端特性章节
- `docs/项目联动与VM流程.md`：更新架构图、新增 B+ 阶段功能清单
- `docs/ARM64固件集成清单.md`：补充 SSE 验证与密码设置步骤
