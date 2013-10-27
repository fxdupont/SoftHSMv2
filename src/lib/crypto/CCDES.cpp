/*
 * Copyright (c) 2013 .SE (The Internet Infrastructure Foundation)
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
 CCDES.cpp

 CommonCrypto (3)DES implementation
 *****************************************************************************/

#include "config.h"
#include "CCDES.h"
#include <algorithm>
#include "odd.h"

CCAlgorithm CCDES::getCipher() const
{
	if (currentKey == NULL) return (CCAlgorithm)~0;

	// Check currentKey bit length; 3DES only supports 56-bit, 112-bit or 168-bit keys
	if ((currentKey->getBitLen() != 56) && 
	    (currentKey->getBitLen() != 112) &&
            (currentKey->getBitLen() != 168))
	{
		ERROR_MSG("Invalid DES currentKey length (%d bits)", currentKey->getBitLen());

		return (CCAlgorithm)~0;
	}

	// People shouldn't really be using 56-bit DES keys, generate a warning
	if (currentKey->getBitLen() == 56)
	{
		DEBUG_MSG("CAUTION: use of 56-bit DES keys is not recommended!");

		return kCCAlgorithmDES;

	}
	else
		return kCCAlgorithm3DES;
}

bool CCDES::generateKey(SymmetricKey& key, RNG* rng /* = NULL */)
{
	if (rng == NULL)
	{
		return false;
	}

	if (key.getBitLen() == 0)
	{
		return false;
	}

	ByteString keyBits;

	// don't count parity bit
	if (!rng->generateRandom(keyBits, key.getBitLen()/7))
	{
		return false;
	}

	// fix the odd parity
	size_t i;
	for (i = 0; i < keyBits.size(); i++)
	{
		keyBits[i] = odd_parity[keyBits[i]];
	}


	return key.setKeyBits(keyBits);
}

size_t CCDES::getBlockSize() const
{
	// The block size is 64 bits
	return kCCBlockSizeDES;
}

