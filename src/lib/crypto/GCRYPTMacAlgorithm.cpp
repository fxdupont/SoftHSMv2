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
 GCRYPTMacAlgorithm.cpp

 libgcrypt MAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "GCRYPTMacAlgorithm.h"

// Constructor
GCRYPTMacAlgorithm::GCRYPTMacAlgorithm()
{
	macHd = NULL;
}

// Destructor
GCRYPTMacAlgorithm::~GCRYPTMacAlgorithm()
{
	if (macHd != NULL)
	{
		gcry_md_close(macHd);
	}
}

// Signing functions
bool GCRYPTMacAlgorithm::signInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	// Initialize the context
	gcry_error_t rv = gcry_md_open(&macHd, getHash(), GCRY_MD_FLAG_HMAC);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("gcry_md_open failed");

		macHd = NULL;

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	rv = gcry_md_setkey(macHd, key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("gcry_md_setkey failed");

		gcry_md_close(macHd);
		macHd = NULL;

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	// Continue signing
	if (dataToSign.size() == 0)
	{
		return true;
	}

	gcry_md_write(macHd, dataToSign.const_byte_str(), dataToSign.size());

	return true;
}

bool GCRYPTMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	signature.resize(gcry_md_get_algo_dlen(getHash()));

	unsigned char* digest = gcry_md_read(macHd, 0);
	if (digest == NULL)
	{
		ERROR_MSG("gcry_md_read failed");

		gcry_md_close(macHd);
		macHd = NULL;

		return false;
	}

	memcpy(&signature[0], digest, signature.size());

	gcry_md_close(macHd);
	macHd = NULL;

	return true;
}

// Verification functions
bool GCRYPTMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	// Initialize the context
	gcry_error_t rv = gcry_md_open(&macHd, getHash(), GCRY_MD_FLAG_HMAC);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("gcry_md_open failed");

		macHd = NULL;

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	rv = gcry_md_setkey(macHd, key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("gcry_md_setkey failed");

		gcry_md_close(macHd);
		macHd = NULL;

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	// Continue verifying
	if (originalData.size() == 0)
	{
		return true;
	}

	gcry_md_write(macHd, originalData.const_byte_str(), originalData.size());

	return true;
}

bool GCRYPTMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	if (signature.size() != gcry_md_get_algo_dlen(getHash()))
	{
		ERROR_MSG("signature size mismatch");

		gcry_md_close(macHd);
		macHd = NULL;

		return false;
	}

	bool ret = true;
	unsigned char* digest = gcry_md_read(macHd, 0);
	if (digest == NULL)
	{
		ERROR_MSG("gcry_md_read failed");

		ret = false;
	}

	ret = ret && (memcmp(signature.const_byte_str(), digest, signature.size()) == 0);

	gcry_md_close(macHd);
	macHd = NULL;

	return ret;
}
