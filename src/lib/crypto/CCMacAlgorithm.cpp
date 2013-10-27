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

// TODO: Store context in securely allocated memory

/*****************************************************************************
 CCMacAlgorithm.cpp

 CommonCrypto MAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "CCMacAlgorithm.h"
#include "salloc.h"

// Destructor
CCMacAlgorithm::~CCMacAlgorithm()
{
	memset(&curCTX, 0, sizeof(curCTX));
}

// Signing functions
bool CCMacAlgorithm::signInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	// Initialize signing
	CCHmacInit(&curCTX, getHash(), key->getKeyBits().const_byte_str(), key->getKeyBits().size());

	return true;
}

bool CCMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	CCHmacUpdate(&curCTX, dataToSign.const_byte_str(), dataToSign.size());

	return true;
}

bool CCMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	signature.resize(getMacSize());
	CCHmacFinal(&curCTX, &signature[0]);

	memset(&curCTX, 0, sizeof(curCTX));

	return true;
}

// Verification functions
bool CCMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	// Initialize signing
	CCHmacInit(&curCTX, getHash(), key->getKeyBits().const_byte_str(), key->getKeyBits().size());

	return true;
}

bool CCMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	CCHmacUpdate(&curCTX, originalData.const_byte_str(), originalData.size());

	return true;
}

bool CCMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString macResult;
	macResult.resize(getMacSize());

	CCHmacFinal(&curCTX, &macResult[0]);

	memset(&curCTX, 0, sizeof(curCTX));

	return macResult == signature;
}
