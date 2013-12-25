AC_DEFUN([ACX_BOTAN_RFC5649],[
	AC_MSG_CHECKING(for Botan RFC5649 support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$LIBS $CRYPTO_LIBS"

	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE([
		AC_LANG_SOURCE([[
			#include <botan/botan.h>
			#include <botan/rfc3394.h>
			int main()
			{
				using namespace Botan;

#if BOTAN_VERSION_MINOR == 11
				secure_vector<byte> key(10);
#else
				SecureVector<byte> key(10);
#endif
				SymmetricKey kek("AABB");
				Algorithm_Factory& af = global_state().algorithm_factory();
#if BOTAN_VERSION_MINOR == 11
				secure_vector<byte> x = rfc5649_keywrap(key, kek, af);
#else
				SecureVector<byte> x = rfc5649_keywrap(key, kek, af);
#endif
				return 1;
			}
		]])
	],[
		AC_MSG_RESULT([Found AES key wrap with pad])
		AC_DEFINE([HAVE_AES_KEY_WRAP_PAD], [1],
			  [Define if advanced AES key wrap with pad is supported])
	],[
		AC_MSG_RESULT([Cannot find AES key wrap with pad])

	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
])
