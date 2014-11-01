/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation)
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
 PSSLMacAlgorithm.cpp

 PolarSSL MAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "PSSLMacAlgorithm.h"

// Base constructor
PSSLMacAlgorithm::PSSLMacAlgorithm()
{
	md_init(&ctx);
}

// Destructor
PSSLMacAlgorithm::~PSSLMacAlgorithm()
{
	md_free(&ctx);
}

// Signing functions
bool PSSLMacAlgorithm::signInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	// Initialize the context
	if (md_init_ctx(&ctx, getHash()) != 0)
	{
		ERROR_MSG("md_init_ctx failed");

		md_free(&ctx);

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	// Initialize signing
	if (md_hmac_starts(&ctx, key->getKeyBits().const_byte_str(), key->getKeyBits().size()) != 0)
	{
		ERROR_MSG("md_hmac_starts failed");

		md_free(&ctx);

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (md_hmac_update(&ctx, dataToSign.const_byte_str(), dataToSign.size()) != 0)
	{
		ERROR_MSG("md_hmac_update failed");

		md_free(&ctx);

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	signature.resize(md_get_size(getHash()));

	if (md_hmac_finish(&ctx, &signature[0]) != 0)
	{
		ERROR_MSG("md_hmac_finish failed");

		md_free(&ctx);

		return false;
	}

	md_free(&ctx);

	return true;
}

// Verification functions
bool PSSLMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	// Initialize the context
	if (md_init_ctx(&ctx, getHash()) != 0)
	{
		ERROR_MSG("md_init_ctx failed");

		md_free(&ctx);

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}


	// Initialize signing
	if (md_hmac_starts(&ctx, key->getKeyBits().const_byte_str(), key->getKeyBits().size()) != 0)
	{
		ERROR_MSG("md_hmac_starts failed");

		md_free(&ctx);

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (md_hmac_update(&ctx, originalData.const_byte_str(), originalData.size()) != 0)
	{
		ERROR_MSG("md_hmac_update failed");

		md_free(&ctx);

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString macResult;
	macResult.resize(md_get_size(getHash()));

	if (md_hmac_finish(&ctx, &macResult[0]) != 0)
	{
		ERROR_MSG("md_hmac_finish failed");

		md_free(&ctx);

		return false;
	}

	md_free(&ctx);

	return macResult == signature;
}
