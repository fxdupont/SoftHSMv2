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

// TODO: Store context in securely allocated memory

/*****************************************************************************
 CPPMacAlgorithm.cpp

 Crypto++ MAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "CPPMacAlgorithm.h"

// Constructor
CPPMacAlgorithm::CPPMacAlgorithm()
{
	hmac = NULL;
}

// Destructor
CPPMacAlgorithm::~CPPMacAlgorithm()
{
	delete hmac;
	hmac = NULL;
}

// Signing functions
bool CPPMacAlgorithm::signInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	// Set key
	try
	{
		hmac->SetKey(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to set the key in sign hmac token");

		hmac->Restart();

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool CPPMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		hmac->Restart();

		return false;
	}

	try
	{
		hmac->Update(dataToSign.const_byte_str(), dataToSign.size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to update the sign hmac token");

		hmac->Restart();

		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool CPPMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	// Perform the signature operation
	signature.resize(hmac->DigestSize());
	try
	{
		hmac->Final(&signature[0]);
	}
	catch (...)
	{
		ERROR_MSG("Could not sign the data");

		hmac->Restart();

		return false;
	}

	hmac->Restart();

	return true;
}

// Verification functions
bool CPPMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	// Call the superclass initialiser
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	// Set key
	try
	{
		hmac->SetKey(key->getKeyBits().const_byte_str(), key->getKeyBits().size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to set the key in verify hmac token");

		hmac->Restart();

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool CPPMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		hmac->Restart();

		return false;
	}

	try
	{
		hmac->Update(originalData.const_byte_str(), originalData.size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to update the verify hmac token");

		hmac->Restart();

		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool CPPMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	// Perform the verify operation
	ByteString macResult;
	macResult.resize(hmac->DigestSize());
	try
	{
		hmac->Final(&macResult[0]);
	}
	catch (...)
	{
		ERROR_MSG("Failed to verify the data");

		hmac->Restart();

		return false;
	}

	hmac->Restart();

	return macResult == signature;
}

size_t CPPMacAlgorithm::getMacSize() const
{
	return hmac->DigestSize();
}
