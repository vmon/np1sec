ACLOCAL_AMFLAGS = -I m4 -I config-aux --install

AM_CXXFLAGS = -Werror -Wall -Wextra -Wformat=2 -std=c++0x

AM_CPPFLAGS = -I. -I$(srcdir)/src \
	-I$(srcdir)/contrib/gtest/include \
	$(LIBGCRYPT_CFLAGS) \
	$(LIBEVENT_CFLAGS)

noinst_LTLIBRARIES =
noinst_PROGRAMS =

TESTS =

lib_LTLIBRARIES = libnp1sec.la

libnp1sec_la_SOURCES = \
	crypt.cc \
	logger.cc \
	base64.cc \
	message.cc \
	participant.cc \
	session.cc \
	room.cc \
	userstate.cc

libnp1sec_la_LIBADD = \
	$(LIBGCRYPT_LIBS) \
	$(LIBEVENT_LIBS)

#include test/Makefile.inc
#include Makefile.am.lint
