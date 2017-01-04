AM_CFLAGS   += -I$(top_srcdir)/platform/$(with_platform)/arch/$(ARCH_DIR) \
	-I$(top_srcdir)/platform/linux-generic/include \
	-I$(top_srcdir)/platform/linux-generic/arch/$(ARCH_DIR)

AM_CXXFLAGS += -I$(top_srcdir)/platform/$(with_platform)/arch/$(ARCH_DIR) \
	-I$(top_srcdir)/platform/linux-generic/include \
	-I$(top_srcdir)/platform/linux-generic/arch/$(ARCH_DIR)

AM_CFLAGS  +=	 -I$(SDK_INSTALL_PATH)/include
AM_LDFLAGS +=	 -L$(SDK_INSTALL_PATH)/lib

LIBS       +=	 -lmusdk
