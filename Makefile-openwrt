#
# Copyright (C) 2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ps3-jupiter
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/ps3-jupiter
  SUBMENU:=Wireless Drivers
  TITLE:=Dirver for PS3 slim WIFI
  FILES:=$(PKG_BUILD_DIR)/ps3_jupiter_sta.$(LINUX_KMOD_SUFFIX) $(PKG_BUILD_DIR)/ps3_jupiter.$(LINUX_KMOD_SUFFIX)
  AUTOLOAD:=$(call AutoLoad,80,ps3_jupiter ps3_jupiter_sta)
endef

define KernelPackage/ps3-jupiter/description
 Driver for ps3 slim wifi
endef

EXTRA_KCONFIG:= \
    

EXTRA_CFLAGS:= \

MAKE_OPTS:= \
    ARCH="$(LINUX_KARCH)" \
    CROSS_COMPILE="$(TARGET_CROSS)" \
    SUBDIRS="$(PKG_BUILD_DIR)" \
    EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
    LINUXINCLUDE="-I$(LINUX_DIR)/include -include linux/autoconf.h -I$(LINUX_DIR)/arch/powerpc/include" \
    $(EXTRA_KCONFIG)

define Build/Prepare
    mkdir -p $(PKG_BUILD_DIR) && \
    $(CP) ./files/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
    $(MAKE) -C "$(LINUX_DIR)" \
        $(MAKE_OPTS) \
        modules
endef

$(eval $(call KernelPackage,ps3-jupiter))
