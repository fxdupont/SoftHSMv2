/*
 * Copyright (c) 2013 SURFnet bv
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
 CCSHA256.h

 CommonCrypto SHA256 implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CCSHA256_H
#define _SOFTHSM_V2_CCSHA256_H

#include "config.h"
#include "HashAlgorithm.h"
#include <CommonCrypto/CommonDigest.h>

class CCSHA256 : public HashAlgorithm
{
public:
	// Base constructors
	CCSHA256() : HashAlgorithm() {
		memset(&curCTX, 0, sizeof(curCTX));
	}

	// Destructor
	~CCSHA256();

	// Hashing functions
	virtual bool hashInit();
	virtual bool hashUpdate(const ByteString& data);
	virtual bool hashFinal(ByteString& hashedData);

	virtual int getHashSize();

private:
	// Current hashing context
	CC_SHA256_CTX curCTX;
};

#endif // !_SOFTHSM_V2_CCSHA256_H

