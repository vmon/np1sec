ACLOCAL_AMFLAGS = -I m4 -I config-aux --install
AM_CXXFLAGS = -Werror -Wall -Wextra -Wformat=2 -std=c++0x
AM_CPPFLAGS = -I../../src -I/usr/include/libtest \
	$(JSONCPP_CFLAGS) \
	$(PURPLE_CFLAGS)
#	$(lib_CPPFLAGS)

noinst_PROGRAMS = jabberite

jabberite_SOURCES = jabberite.cc \
                    jabberite_np1sec_plugin.cc \
					ec_api.cc

jabberite_LDADD = \
	$(PURPLE_LIBS) \
	$(JSONCPP_LIBS) \
	../../src/libnp1sec.la


# jabberite_CPPFLAGS = \
# 	$(PURPLE_CFLAGS) \
# 	$(JSONCPP_CFLAGS) \
# 	-I../../src \
# 	-I/usr/include
