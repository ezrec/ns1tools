
AM_CFLAGS=-Wall -Werror 

bin_PROGRAMS = ns1tosql ns1totxt

lib_LTLIBRARIES= libns1.la

include_HEADERS = ns1.h

libns1_la_SOURCES = ns1.c

ns1tosql_SOURCES = ns1tosql.c
ns1tosql_LDADD = libns1.la

ns1totxt_SOURCES = ns1totxt.c
ns1totxt_LDADD = libns1.la
