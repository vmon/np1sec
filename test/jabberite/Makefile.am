ACLOCAL_AMFLAGS = -I config-aux --install
AM_CXXFLAGS = -Werror -Wall -Wextra -Wformat=2 -std=c++0x
AM_CPPFLAGS = -I. -I../../src -I/usr/include/libtest \
	$(lib_CPPFLAGS)

noinst_PROGRAMS = jabberite

jabberite_SOURCES = jabberite.cc \
                    jabberite_np1sec_plugin.cc

jabberite_LDADD = \
	$(PURPLE_LIBS) \
	../../src/libnp1sec.la

jabberite_CPPFLAGS = \
	$(PURPLE_CFLAGS) \
	-I../../src
