#!/bin/sh
aclocal
autoheader
libtoolize --force
automake --add-missing
autoconf
