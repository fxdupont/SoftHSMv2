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

// TODO: Store cryptor context in securely allocated memory

/*****************************************************************************
 CCSymmetricAlgorithm.cpp

 CommonCrypto symmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "CCSymmetricAlgorithm.h"

// Constructor
CCSymmetricAlgorithm::CCSymmetricAlgorithm()
{
	cryptorref = NULL;
}

// Destructor
CCSymmetricAlgorithm::~CCSymmetricAlgorithm()
{
	if (cryptorref != NULL)
	{
		CCCryptorRelease(cryptorref);
	}
	cryptorref = NULL;
}

// Encryption functions
bool CCSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString()*/, bool padding /* = true */)
{
	// Call the superclass initialiser
	if (!SymmetricAlgorithm::encryptInit(key, mode, IV, padding))
	{
		return false;
	}

	// Check the IV
	if ((IV.size() > 0) && (IV.size() != getBlockSize()))
	{
		ERROR_MSG("Invalid IV size (%d bytes, expected %d bytes)", IV.size(), getBlockSize());

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	ByteString iv;

	if (IV.size() > 0)
	{
		iv = IV;
	}
	else
	{
		iv.wipe(getBlockSize());
	}

	// Set Options
	CCOptions options = 0;

	if (padding)
	{
		options |= kCCOptionPKCS7Padding;
	}

	if (!mode.compare("ecb"))
	{
		options |= kCCOptionECBMode;
	}
	else if (mode.compare("cbc"))
	{
		ERROR_MSG("Invalid cipher mode %s", mode.c_str());

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Determine the cipher algorithm
	const CCAlgorithm cipher = getCipher();

	if (cipher == (CCAlgorithm)~0)
	{
		ERROR_MSG("Invalid encryption cipher");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	ByteString keyData(key->getKeyBits());

	// Adjust 3DES EDE
	if ((cipher == kCCAlgorithm3DES) && (key->getBitLen() == 112))
	{
		keyData += keyData.substr(0, 8);
	}

	// Allocate the context
	CCCryptorStatus status = CCCryptorCreate(kCCEncrypt, cipher, options, keyData.const_byte_str(), keyData.size(), iv.const_byte_str(), &cryptorref);

	if (status != kCCSuccess)
	{
		ERROR_MSG("Failed to create CCCryptorRef: %d", (int) status);

		if (cryptorref != NULL)
			CCCryptorRelease(cryptorref);
		cryptorref = NULL;

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	return true;
}

bool CCSymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptUpdate(data, encryptedData))
	{
		if (cryptorref != NULL)
		{
			CCCryptorRelease(cryptorref);
		}
		cryptorref = NULL;

		return false;
	}

	if (data.size() == 0)
	{
		encryptedData.resize(0);

		return true;
	}

	// Prepare the output block
	encryptedData.resize(CCCryptorGetOutputLength(cryptorref, data.size(), false));

	size_t outLen = encryptedData.size();
	CCCryptorStatus status = CCCryptorUpdate(cryptorref, data.const_byte_str(), data.size(), &encryptedData[0], outLen, &outLen);

	if (status != kCCSuccess)
	{
		ERROR_MSG("CCCryptorUpdate failed: %d", (int) status);

		if (cryptorref != NULL)
			CCCryptorRelease(cryptorref);
		cryptorref = NULL;

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Resize the output block
	encryptedData.resize(outLen);

	return true;
}

bool CCSymmetricAlgorithm::encryptFinal(ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptFinal(encryptedData))
	{
		if (cryptorref != NULL)
		{
			CCCryptorRelease(cryptorref);
		}
		cryptorref = NULL;

		return false;
	}

	// Prepare the output block
	encryptedData.resize(CCCryptorGetOutputLength(cryptorref, 0, true));

	size_t outLen = encryptedData.size();
	CCCryptorStatus status = CCCryptorFinal(cryptorref, &encryptedData[0], outLen, &outLen);

	if (status != kCCSuccess)
	{
		ERROR_MSG("CCCryptorFinal failed: %d", (int) status);

		if (cryptorref != NULL)
			CCCryptorRelease(cryptorref);
		cryptorref = NULL;

		return false;
	}

	// Resize the output block
	encryptedData.resize(outLen);

	if (cryptorref != NULL)
		CCCryptorRelease(cryptorref);
	cryptorref = NULL;

	return true;
}

// Decryption functions
bool CCSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString() */, bool padding /* = true */)
{
	// Call the superclass initialiser
	if (!SymmetricAlgorithm::decryptInit(key, mode, IV, padding))
	{
		return false;
	}

	// Check the IV
	if ((IV.size() > 0) && (IV.size() != getBlockSize()))
	{
		ERROR_MSG("Invalid IV size (%d bytes, expected %d bytes)", IV.size(), getBlockSize());

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	ByteString iv;

	if (IV.size() > 0)
	{
		iv = IV;
	}
	else
	{
		iv.wipe(getBlockSize());
	}

	// Set Options
	CCOptions options = 0;

	if (padding)
	{
		options |= kCCOptionPKCS7Padding;
	}

	if (!mode.compare("ecb"))
	{
		options |= kCCOptionECBMode;
	}
	else if (mode.compare("cbc"))
	{
		ERROR_MSG("Invalid cipher mode %s", mode.c_str());

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Determine the cipher algorithm
	const CCAlgorithm cipher = getCipher();

	if (cipher == (CCAlgorithm)~0)
	{
		ERROR_MSG("Invalid decryption cipher");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	ByteString keyData(key->getKeyBits());

	// Adjust 3DES EDE
	if ((cipher == kCCAlgorithm3DES) && (key->getBitLen() == 112))
	{
		keyData += keyData.substr(0, 8);
	}

	// Allocate the context
	CCCryptorStatus status = CCCryptorCreate(kCCDecrypt, cipher, options, keyData.const_byte_str(), keyData.size(), iv.const_byte_str(), &cryptorref);

	if (status != kCCSuccess)
	{
		ERROR_MSG("Failed to create CCCryptorRef: %d", (int) status);

		if (cryptorref == NULL)
			CCCryptorRelease(cryptorref);
		cryptorref = NULL;

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	return true;
}

bool CCSymmetricAlgorithm::decryptUpdate(const ByteString& encryptedData, ByteString& data)
{
	if (!SymmetricAlgorithm::decryptUpdate(encryptedData, data))
	{
		if (cryptorref != NULL)
		{
			CCCryptorRelease(cryptorref);
		}
		cryptorref = NULL;

		return false;
	}

	// Prepare the output block
	data.resize(CCCryptorGetOutputLength(cryptorref, encryptedData.size(), false));

	size_t outLen = data.size();

	DEBUG_MSG("Decrypting %d bytes into buffer of %d bytes", encryptedData.size(), data.size());

	CCCryptorStatus status = CCCryptorUpdate(cryptorref, encryptedData.const_byte_str(), encryptedData.size(), &data[0], outLen, &outLen);

	if (status != kCCSuccess)
	{
		ERROR_MSG("CCCryptorUpdate failed: %d", (int) status);

		if (cryptorref != NULL)
			CCCryptorRelease(cryptorref);
		cryptorref = NULL;

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	DEBUG_MSG("Decrypt returned %d bytes of data", outLen);

	// Resize the output block
	data.resize(outLen);

	return true;
}

bool CCSymmetricAlgorithm::decryptFinal(ByteString& data)
{
	if (!SymmetricAlgorithm::decryptFinal(data))
	{
		if (cryptorref != NULL)
		{
			CCCryptorRelease(cryptorref);
		}
		cryptorref = NULL;

		return false;
	}

	// Prepare the output block
	data.resize(CCCryptorGetOutputLength(cryptorref, 0, true));

	size_t outLen = data.size();
	CCCryptorStatus status = CCCryptorFinal(cryptorref, &data[0], outLen, &outLen);

	if (status != kCCSuccess)
	{
		ERROR_MSG("CCCryptorFinal failed: %d", (int) status);

		if (cryptorref != NULL)
			CCCryptorRelease(cryptorref);
		cryptorref = NULL;

		return false;
	}

	// Resize the output block
	data.resize(outLen);

	if (cryptorref != NULL)
		CCCryptorRelease(cryptorref);
	cryptorref = NULL;

	return true;
}

