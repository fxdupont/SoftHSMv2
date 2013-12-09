/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 CPPAES.cpp

 Crypto++ AES implementation
 *****************************************************************************/

#include "config.h"
#include "CPPAES.h"
#include <algorithm>

#include <cryptopp/aes.h>

CryptoPP::BlockCipher* CPPAES::getCipher(bool wantenc) const
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

	if (wantenc)
	{

		CryptoPP::BlockCipher* enc = NULL;

		try
		{
			enc = new CryptoPP::AES::Encryption(currentKey->getKeyBits().const_byte_str(), currentKey->getKeyBits().size());
		}
		catch (...)
		{
			ERROR_MSG("Failed to create the encryption token");

			return NULL;
		}

		return enc;
	}
	else
	{

		CryptoPP::BlockCipher* dec = NULL;

		try
		{
			dec = new CryptoPP::AES::Decryption(currentKey->getKeyBits().const_byte_str(), currentKey->getKeyBits().size());
		}
		catch (...)
		{
			ERROR_MSG("Failed to create the decryption token");

			return NULL;
		}

		return dec;
	}
}

size_t CPPAES::getBlockSize() const
{
	// The block size is 128 bits
	return 128 >> 3;
}

