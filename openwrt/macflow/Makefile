include $(TOPDIR)/rules.mk

PKG_NAME:=macflow
PKG_VERSION:=$(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' | tr -d '\n' || echo 3.0.0)
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=macflow

MACFLOW_SRC_DIR?=$(CURDIR)/src

# Go 版：查找预编译二进制
MACFLOW_GO_BIN?=$(MACFLOW_SRC_DIR)/backend-go/macflowd-arm64

# 回退：检查仓库根目录
ifeq ($(wildcard $(MACFLOW_GO_BIN)),)
  ifneq ($(wildcard $(CURDIR)/../../backend-go/macflowd-arm64),)
    MACFLOW_GO_BIN:=$(CURDIR)/../../backend-go/macflowd-arm64
  endif
endif

include $(INCLUDE_DIR)/package.mk

define Package/macflow
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MACFlow split routing and DNS shield
  URL:=https://github.com/example/macflow
  DEPENDS:=+bash +ip-full +nftables-json +kmod-tun +kmod-nft-nat +sing-box +curl +ca-bundle +ca-certificates +luci-base
endef

define Package/macflow/description
MAC-based split routing with fail-close guard, DNS leak protection,
3x-ui source sync, and realtime web panel for iStoreOS/OpenWrt.
Go native binary — zero runtime dependencies.
endef

define Package/macflow/conffiles
/etc/config/macflow
/opt/macflow/data/auth.json
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	@test -f "$(MACFLOW_GO_BIN)" || { \
		echo "[macflow] Go binary not found: $(MACFLOW_GO_BIN)"; \
		echo "[macflow] Build it first:"; \
		echo "  cd backend-go && GOOS=linux GOARCH=arm64 go build -ldflags='-s -w' -o macflowd-arm64 ./cmd/macflowd/"; \
		false; \
	}
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/bin
	$(CP) $(MACFLOW_GO_BIN) $(PKG_BUILD_DIR)/bin/macflowd
	$(CP) $(MACFLOW_SRC_DIR)/web $(PKG_BUILD_DIR)/
	$(CP) $(MACFLOW_SRC_DIR)/core $(PKG_BUILD_DIR)/
	$(CP) $(MACFLOW_SRC_DIR)/config $(PKG_BUILD_DIR)/
	$(CP) $(MACFLOW_SRC_DIR)/scripts $(PKG_BUILD_DIR)/
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/vm-tests
	$(CP) $(MACFLOW_SRC_DIR)/vm/run-all-tests.sh $(PKG_BUILD_DIR)/vm-tests/
	$(CP) $(MACFLOW_SRC_DIR)/vm/final-check.sh $(PKG_BUILD_DIR)/vm-tests/
	$(CP) $(MACFLOW_SRC_DIR)/vm/test-*.sh $(PKG_BUILD_DIR)/vm-tests/
endef

define Build/Compile
endef

define Package/macflow/install
	# 主二进制
	$(INSTALL_DIR) $(1)/opt/macflow
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/macflowd $(1)/opt/macflow/macflowd

	# 静态资源与配置
	$(CP) $(PKG_BUILD_DIR)/web $(1)/opt/macflow/
	$(CP) $(PKG_BUILD_DIR)/core $(1)/opt/macflow/
	$(CP) $(PKG_BUILD_DIR)/config $(1)/opt/macflow/
	$(CP) $(PKG_BUILD_DIR)/scripts $(1)/opt/macflow/
	$(INSTALL_DIR) $(1)/opt/macflow/vm
	$(CP) $(PKG_BUILD_DIR)/vm-tests/* $(1)/opt/macflow/vm/
	$(INSTALL_DIR) $(1)/opt/macflow/data

	# 系统集成
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/macflow $(1)/etc/init.d/macflow
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/macflow $(1)/etc/config/macflow
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/etc/hotplug.d/iface/99-macflow $(1)/etc/hotplug.d/iface/99-macflow

	# 工具
	$(INSTALL_DIR) $(1)/usr/libexec/macflow
	$(INSTALL_BIN) ./files/usr/libexec/macflow/upgrade.sh $(1)/usr/libexec/macflow/upgrade.sh
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/macflow-selfcheck $(1)/usr/bin/macflow-selfcheck

	# LuCI 集成
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/controller/macflow.lua $(1)/usr/lib/lua/luci/controller/macflow.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/macflow
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/view/macflow/selfcheck.htm $(1)/usr/lib/lua/luci/view/macflow/selfcheck.htm
endef

define Package/macflow/preinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
[ -x /usr/libexec/macflow/upgrade.sh ] && /usr/libexec/macflow/upgrade.sh preinst || true
exit 0
endef

define Package/macflow/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
[ -x /usr/libexec/macflow/upgrade.sh ] && /usr/libexec/macflow/upgrade.sh postinst || true
/etc/init.d/macflow enable >/dev/null 2>&1 || true
/etc/init.d/macflow restart >/dev/null 2>&1 || true
exit 0
endef

define Package/macflow/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/macflow stop >/dev/null 2>&1 || true
/etc/init.d/macflow disable >/dev/null 2>&1 || true
exit 0
endef

$(eval $(call BuildPackage,macflow))
