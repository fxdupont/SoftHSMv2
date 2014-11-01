/*
 * Copyright (c) 2014 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 PSSLAES.cpp

 PolarSSL AES implementation
 *****************************************************************************/

#include "config.h"
#include "PSSLAES.h"
#include <algorithm>
#include <polarssl/cipher.h>

// Wrap/Unwrap keys
bool PSSLAES::wrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("PolarSSL does not support key wrapping");

	return false;
}

bool PSSLAES::unwrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("PolarSSL does not support key wrapping");

	return false;
}

const cipher_info_t* PSSLAES::getCipher() const
{
	if (currentKey == NULL) return NULL;

	// Check currentKey bit length; AES only supports 128, 192 or 256 bit keys
	if ((currentKey->getBitLen() != 128) &&
	    (currentKey->getBitLen() != 192) &&
            (currentKey->getBitLen() != 256))
	{
		ERROR_MSG("Invalid AES currentKey length (%d bits)", currentKey->getBitLen());

		return NULL;
	}

	// Determine the cipher mode
	if (currentCipherMode == SymMode::CBC)
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return cipher_info_from_type(POLARSSL_CIPHER_AES_128_CBC);
			case 192:
				return cipher_info_from_type(POLARSSL_CIPHER_AES_192_CBC);
			case 256:
				return cipher_info_from_type(POLARSSL_CIPHER_AES_256_CBC);
		};
	}
	else if (currentCipherMode == SymMode::ECB)
	{
		switch(currentKey->getBitLen())
		{
			case 128:
				return cipher_info_from_type(POLARSSL_CIPHER_AES_128_ECB);
			case 192:
				return cipher_info_from_type(POLARSSL_CIPHER_AES_192_ECB);
			case 256:
				return cipher_info_from_type(POLARSSL_CIPHER_AES_256_ECB);
		};
	}

	ERROR_MSG("Invalid AES cipher mode %i", currentCipherMode);

	return NULL;
}

size_t PSSLAES::getBlockSize() const
{
	// The block size is 128 bits
	return 128 >> 3;
}

