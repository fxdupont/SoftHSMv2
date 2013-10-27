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
 CCSHA1.cpp

 CommonCrypto SHA1 implementation
 *****************************************************************************/

#include "config.h"
#include "CCSHA1.h"

// Destructor
CCSHA1::~CCSHA1()
{
	memset(&curCTX, 0, sizeof(curCTX));
}

// Hashing functions
bool CCSHA1::hashInit()
{
	if (!HashAlgorithm::hashInit())
	{
		return false;
	}

	// Initialize the context
	if (CC_SHA1_Init(&curCTX) != 1)
	{
		ERROR_MSG("CC_SHA1_Init failed");

		memset(&curCTX, 0, sizeof(curCTX));

		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);

		return false;
	}

	return true;
}

bool CCSHA1::hashUpdate(const ByteString& data)
{
	if (!HashAlgorithm::hashUpdate(data))
	{
		return false;
	}

	// Continue digesting
	if (data.size() == 0)
	{
		return true;
	}

	if (CC_SHA1_Update(&curCTX, data.const_byte_str(), (CC_LONG) data.size()) != 1)
	{
		ERROR_MSG("CC_SHA1_Update failed");

		memset(&curCTX, 0, sizeof(curCTX));

		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);

		return false;
	}

	return true;
}

bool CCSHA1::hashFinal(ByteString& hashedData)
{
	if (!HashAlgorithm::hashFinal(hashedData))
	{
		return false;
	}

	hashedData.resize(CC_SHA1_DIGEST_LENGTH);

	if (CC_SHA1_Final(&hashedData[0], &curCTX) != 1)
	{
		ERROR_MSG("CC_SHA1_Final failed");

		memset(&curCTX, 0, sizeof(curCTX));

		return false;
	}

	memset(&curCTX, 0, sizeof(curCTX));

	return true;
}

int CCSHA1::getHashSize()
{
	return CC_SHA1_DIGEST_LENGTH;
}
