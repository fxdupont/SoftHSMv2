AC_DEFUN([ACX_POLARSSL_ECC],[
	AC_MSG_CHECKING(for PolarSSL ECC support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$LIBS $CRYPTO_LIBS"

	AC_LANG_PUSH([C])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <polarssl/ecdsa.h>
			int main()
			{
				ecp_curve_info *ec256, *ec384;

				ec256 = ecp_curve_info_from_name("secp256r1");
				ec384 = ecp_curve_info_from_name("secp384r1");
				if (ec256 == NULL || ec384 == NULL)
					return 1;
				return 0;
			}
		]])
	],[
		AC_MSG_RESULT([Found P256 and P384])
	],[
		AC_MSG_RESULT([Cannot find P256 or P384])
		AC_MSG_ERROR([PolarSSL library has no ECC support])
	],[])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
