#
# This software is licensed under the Public Domain.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=babeld-utils
PKG_RELEASE:=1

PKG_MAINTAINER:=Nick Hainke <vincent@systemli.org>

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/babeld-utils
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Babel Utils
  URL:=https://github.com/PolynomialDivision/babeld-utils.git
  DEPENDS:=+libubus +libubox +libblobmsg-json +libowipcalc
endef

define Package/babeld-utils/description
  This packages implements certain features to allow a more faster interaction with babeld.
endef

define Package/babeld-utils/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/babeld-utils $(1)/usr/sbin/babeld-utils
endef

$(eval $(call BuildPackage,babeld-utils))
