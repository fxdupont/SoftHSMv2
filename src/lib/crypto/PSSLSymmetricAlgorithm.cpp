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

// TODO: Store context in securely allocated memory

/*****************************************************************************
 PSSLSymmetricAlgorithm.cpp

 PolarSSL symmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "PSSLSymmetricAlgorithm.h"
#include "salloc.h"

// Constructor
PSSLSymmetricAlgorithm::PSSLSymmetricAlgorithm()
{
	cipher_init(&ctx);
}

// Destructor
PSSLSymmetricAlgorithm::~PSSLSymmetricAlgorithm()
{
	cipher_free(&ctx);
}

// Encryption functions
bool PSSLSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& IV /* = ByteString()*/, bool padding /* = true */)
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

	// Initialize the context
	if (cipher_init_ctx(&ctx, getCipher()) != 0)
	{
		ERROR_MSG("Failed to initialise encrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Set the key
	if (cipher_setkey(&ctx, currentKey->getKeyBits().const_byte_str(), currentKey->getBitLen(), POLARSSL_ENCRYPT) != 0)
	{
		ERROR_MSG("Failed to set encrypt key");

		cipher_free(&ctx);

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Set the padding mode
	if (cipher_set_padding_mode(&ctx, padding ? POLARSSL_PADDING_PKCS7 : POLARSSL_PADDING_NONE) != 0)
	{
		ERROR_MSG("Failed to set padding mode");

		cipher_free(&ctx);

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Set the init vector
	if ((mode != SymMode::ECB) &&
	    (cipher_set_iv(&ctx, iv.const_byte_str(), iv.size()) != 0))
	{
		ERROR_MSG("Failed to set init vector");

		cipher_free(&ctx);

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLSymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptUpdate(data, encryptedData))
	{
		cipher_free(&ctx);

		return false;
	}

	if (data.size() == 0)
	{
		encryptedData.resize(0);

		return true;
	}

	// Prepare the output block
	encryptedData.resize(data.size() + getBlockSize());

	size_t outLen = encryptedData.size();
	if (cipher_update(&ctx, data.const_byte_str(), data.size(), &encryptedData[0], &outLen) != 0)
	{
		ERROR_MSG("cipher_update failed");

		cipher_free(&ctx);

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Resize the output block
	encryptedData.resize(outLen);

	return true;
}

bool PSSLSymmetricAlgorithm::encryptFinal(ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptFinal(encryptedData))
	{
		cipher_free(&ctx);

		return false;
	}

	// Prepare the output block
	encryptedData.resize(getBlockSize());

	size_t outLen = encryptedData.size();

	if (cipher_finish(&ctx, &encryptedData[0], &outLen) != 0)
	{
		ERROR_MSG("cipher_finish failed");

		cipher_free(&ctx);

		return false;
	}

	// Resize the output block
	encryptedData.resize(outLen);

	cipher_free(&ctx);

	return true;
}

// Decryption functions
bool PSSLSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& IV /* = ByteString() */, bool padding /* = true */)
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

	// Initialize the context
	if (cipher_init_ctx(&ctx, getCipher()) != 0)
	{
		ERROR_MSG("Failed to initialise decrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Set the key
	if (cipher_setkey(&ctx, currentKey->getKeyBits().const_byte_str(), currentKey->getBitLen(), POLARSSL_DECRYPT) != 0)
	{
		ERROR_MSG("Failed to set decrypt key");

		cipher_free(&ctx);

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Set the padding mode
	if (cipher_set_padding_mode(&ctx, padding ? POLARSSL_PADDING_PKCS7 : POLARSSL_PADDING_NONE) != 0)
	{
		ERROR_MSG("Failed to set padding mode");

		cipher_free(&ctx);

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Set the init vector
	if ((mode != SymMode::ECB) &&
	    (cipher_set_iv(&ctx, iv.const_byte_str(), iv.size()) != 0))
	{
		ERROR_MSG("Failed to set init vector");

		cipher_free(&ctx);

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLSymmetricAlgorithm::decryptUpdate(const ByteString& encryptedData, ByteString& data)
{
	if (!SymmetricAlgorithm::decryptUpdate(encryptedData, data))
	{
		cipher_free(&ctx);

		return false;
	}

	// Prepare the output block
	data.resize(encryptedData.size() + getBlockSize());

	size_t outLen = data.size();

	DEBUG_MSG("Decrypting %d bytes into buffer of %d bytes", encryptedData.size(), data.size());

	if (cipher_update(&ctx, encryptedData.const_byte_str(), encryptedData.size(), &data[0], &outLen) != 0)
	{
		ERROR_MSG("cipher_update failed");

		cipher_free(&ctx);

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	DEBUG_MSG("Decrypt returned %d bytes of data", outLen);

	// Resize the output block
	data.resize(outLen);

	return true;
}

bool PSSLSymmetricAlgorithm::decryptFinal(ByteString& data)
{
	if (!SymmetricAlgorithm::decryptFinal(data))
	{
		cipher_free(&ctx);

		return false;
	}

	// Prepare the output block
	data.resize(getBlockSize());

	size_t outLen = data.size();

	if (cipher_finish(&ctx, &data[0], &outLen) != 0)
	{
		ERROR_MSG("cipher_finish failed");

		cipher_free(&ctx);

		return false;
	}

	// Resize the output block
	data.resize(outLen);

	cipher_free(&ctx);

	return true;
}

