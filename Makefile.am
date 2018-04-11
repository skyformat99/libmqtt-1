ACLOCAL_AMFLAGS = -I m4

include_HEADERS = mqtt.h libmqtt.h

EXTRA_DIST =  lib/ae.h lib/anet.h lib/fmacros.h lib/zmalloc.h lib/config.h lib/ae_epoll.c lib/ae_evport.c lib/ae_kqueue.c lib/ae_select.c

bin_PROGRAMS = libmqtt_pub libmqtt_sub libmqtt_cmd

libmqtt_pub_SOURCES = libmqtt_pub.c lib/ae.c lib/anet.c lib/zmalloc.c
libmqtt_pub_CFLAGS = -Wall -Werror -Wextra
libmqtt_pub_LDFLAGS =
libmqtt_pub_LDADD =

libmqtt_sub_SOURCES = libmqtt_sub.c lib/ae.c lib/anet.c lib/zmalloc.c
libmqtt_sub_CFLAGS = -Wall -Werror -Wextra
libmqtt_sub_LDFLAGS =
libmqtt_sub_LDADD =

libmqtt_cmd_SOURCES = libmqtt_cmd.c lib/ae.c lib/anet.c lib/zmalloc.c
libmqtt_cmd_CFLAGS = -Wall -Werror -Wextra
libmqtt_cmd_LDFLAGS =
libmqtt_cmd_LDADD =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmqtt.pc
