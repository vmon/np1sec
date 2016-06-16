# Unit tests
AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I config-aux --install
AM_CXXFLAGS = -Werror -Wall -Wextra -Wformat=2 -std=c++0x
AM_CPPFLAGS = -I. -I$(srcdir)/src \
	$(lib_CPPFLAGS)

noinst_PROGRAMS = libnp1sec_test

TESTS = libnp1sec_test

GTEST_SOURCES = \
	../contrib/gtest/src/gtest_main.cc \
	../contrib/gtest/src/gtest-all.cc

libnp1sec_test_SOURCES = \
	$(GTEST_SOURCES) \
	crypt_test.cc \
	test_logger.cc \
	chat_mocker.cc \
	chat_mocker_timered.cc \
	chat_mocker_np1sec_plugin.cc \
	test_message.cc \
	session_test.cc \
	timered_session_test.cc

libnp1sec_test_CPPFLAGS = \
	-I$(top_srcdir)/${GTEST_BASE} \
	-I$(top_srcdir)/${GTEST_INCLUDE} \
	$(LIBGCRYPT_CFLAGS) \
	$(LIBEVENT_CFLAGS)

libnp1sec_test_LDADD = \
	../src/libnp1sec.la \
	$(LIBGCRYPT_LIBS) \
	$(LIBEVENT_LIBS)

libnp1sec_test_LDFLAGS = \
	$(PTHREAD)

# Network condition tests

# noinst_PROGRAMS += chamber_client

# chamber_client_SOURCES = \
# 	test/chamberclient.cc \
# 	test/mongoose.c \
# 	test/jsoncpp.cpp

# chamber_client_LDADD = \
# 	libnp1sec.la \
# 	$(LIBGCRYPT_LIBS) \
# 	$(LIBEVENT_LIBS)

# Integration tests

# noinst_PROGRAMS += xmpp_test

# xmpp_test_SOURCES = test/xmpp_test.cpp

# xmpp_test_LDADD = \
# 	$(PURPLE_LIBS) \
# 	libnp1sec.la

# xmpp_test_CPPFLAGS = \
# 	$(PURPLE_CFLAGS) \
# 	$(LIBGCRYPT_CFLAGS) \
# 	$(LIBEVENT_CFLAGS) \
# 	-I$(srcdir)/src

# gtest

