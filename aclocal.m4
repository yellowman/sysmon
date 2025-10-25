dnl
dnl Add a search path to the LIBS and CFLAGS variables
dnl Searches common library directories: lib, lib64, lib32, multiarch
dnl
AC_DEFUN(AC_ADD_SEARCH_PATH,[
  if test "x$1" != x -a -d $1; then
     dnl Add library search paths (try multiple common directories)
     if test -d $1/lib64; then
       LDFLAGS="-L$1/lib64 $LDFLAGS"
     fi
     if test -d $1/lib/x86_64-linux-gnu; then
       LDFLAGS="-L$1/lib/x86_64-linux-gnu $LDFLAGS"
     fi
     if test -d $1/lib; then
       LDFLAGS="-L$1/lib $LDFLAGS"
     fi
     if test -d $1/lib32; then
       LDFLAGS="-L$1/lib32 $LDFLAGS"
     fi
     dnl Add include search path
     if test -d $1/include; then
        CPPFLAGS="-I$1/include $CPPFLAGS"
     fi
  fi
])

