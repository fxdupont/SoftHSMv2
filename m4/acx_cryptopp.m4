AC_DEFUN([ACX_CRYPTOPP],[
	AC_ARG_WITH(cryptopp,
        	AC_HELP_STRING([--with-cryptopp=PATH],[Specify prefix of path of Crypto++]),
		[
			CRYPTOPP_PATH="$withval"
		],
		[
			CRYPTOPP_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the Crypto++ includes)
	CRYPTOPP_INCLUDES="-I$CRYPTOPP_PATH/include"
	AC_MSG_RESULT($CRYPTOPP_INCLUDES)

	AC_MSG_CHECKING(what are the Crypto++ libs)
	CRYPTOPP_LIBS="-L$CRYPTOPP_PATH/lib -lcryptopp"
	AC_MSG_RESULT($CRYPTOPP_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTOPP_INCLUDES"
	LIBS="$LIBS $CRYPTOPP_LIBS"

	AC_LANG_PUSH([C++])
	AC_CHECK_HEADERS([cryptopp/cryptlib.h],,[AC_MSG_ERROR([Can't find Crypto++ headers])])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(CRYPTOPP_INCLUDES)
	AC_SUBST(CRYPTOPP_LIBS)
])
