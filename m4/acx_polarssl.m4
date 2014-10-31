AC_DEFUN([ACX_POLARSSL],[
	AC_ARG_WITH(polarssl,
        	AC_HELP_STRING([--with-polarssl=PATH],[Specify prefix of path of PolarSSL]),
		[
			POLARSSL_PATH="$withval"
		],
		[
			POLARSSL_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the PolarSSL includes)
	POLARSSL_INCLUDES="-I$POLARSSL_PATH/include"
	AC_MSG_RESULT($POLARSSL_INCLUDES)

	AC_MSG_CHECKING(what are the PolarSSL libs)
	POLARSSL_LIBS="-L$POLARSSL_PATH/lib -lpolarssl"
	AC_MSG_RESULT($POLARSSL_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $POLARSSL_INCLUDES"
	LIBS="$LIBS $POLARSSL_LIBS"

	AC_CHECK_HEADERS([polarssl/version.h],,[AC_MSG_ERROR([Can't find PolarSSL headers])])
	AC_CHECK_LIB(polarssl, mpi_init,,[AC_MSG_ERROR([Can't find PolarSSL library])])

	AC_MSG_CHECKING([for PolarSSL version])
	CHECK_POLARSSL_VERSION=m4_format(0x%02x%02x%02x00L, $1, $2, $3)
	AC_LANG_PUSH([C])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <polarssl/version.h>
			int main()
			{
			#ifndef POLARSSL_VERSION_NUMBER
				return -1;
			#endif
			#if POLARSSL_VERSION_NUMBER >= $CHECK_POLARSSL_VERSION
				return 0;
			#else
				return 1;
			#endif
			}
		]])
	],[
		AC_MSG_RESULT([>= $1.$2.$3])
	],[
		AC_MSG_RESULT([< $1.$2.$3])
		AC_MSG_ERROR([PolarSSL library too old ($1.$2.$3 or later required)])
	],[])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(POLARSSL_INCLUDES)
	AC_SUBST(POLARSSL_LIBS)
])
