##
## Process this file with automake to produce Makefile.in
##

INCLUDES = -I$(top_srcdir)/include

lib_LTLIBRARIES = libiksemelpas.la

libiksemelpas_la_SOURCES = \
	ikstack.c \
	utility.c \
	iks.c \
	sax.c \
	dom.c \
	mystream.c \
	sha.c \
	jabber.c \
	filter.c \
	md5.c \
	base64.c

libiksemelpas_la_LDFLAGS = -version-info 4:1:1 -no-undefined
libiksemelpas_la_CFLAGS = $(CFLAGS)
