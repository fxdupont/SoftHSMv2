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
 CPPSymmetricAlgorithm.cpp

 Crypto++ symmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "CPPSymmetricAlgorithm.h"

#include <cryptopp/modes.h>
#include <cryptopp/seckey.h>

// Constructor
CPPSymmetricAlgorithm::CPPSymmetricAlgorithm()
{
	cipher = NULL;
}

// Destructor
CPPSymmetricAlgorithm::~CPPSymmetricAlgorithm()
{
	delete cipher;
	cipher = NULL;
}

// Encipher functions
bool CPPSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString()*/, bool padding /* = true */)
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

	// Determine the encryptor
	CryptoPP::BlockCipher* enc = getCipher(true);

	if (enc == NULL)
	{
		ERROR_MSG("Invalid encryptor");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Set the padding mode (PCKS7 or NoPadding)
	CryptoPP::StreamTransformationFilter::BlockPaddingScheme paddingScheme = CryptoPP::StreamTransformationFilter::NO_PADDING;
	if (padding)
	{
		paddingScheme = CryptoPP::StreamTransformationFilter::PKCS_PADDING;
	}

	CryptoPP::StreamTransformation* encTrans = NULL;

	try
	{
		if (!mode.compare("cbc"))
		{
			encTrans = new CryptoPP::CBC_Mode_ExternalCipher::Encryption(*enc, IV.const_byte_str());
		}
		else if (!mode.compare("ecb"))
		{
			encTrans = new CryptoPP::ECB_Mode_ExternalCipher::Encryption(*enc);
		}
		else if (!mode.compare("ofb"))
		{
			encTrans = new CryptoPP::OFB_Mode_ExternalCipher::Encryption(*enc, IV.const_byte_str());
		}
		else if (!mode.compare("cfb"))
		{
			encTrans = new CryptoPP::CFB_Mode_ExternalCipher::Encryption(*enc, IV.const_byte_str());
		}
		else
		{
			ERROR_MSG("Invalid cipher mode %s", mode.c_str());
		}
	}
	catch (...)
	{
		ERROR_MSG("Failed to create the encryption token");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	if (encTrans == NULL)
	{
		ERROR_MSG("Failed to create the encryption token");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	try
	{
		cipher = new CryptoPP::StreamTransformationFilter(*encTrans, NULL, paddingScheme);
	}
	catch (...)
	{
		ERROR_MSG("Failed to create the encryption token");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		delete encTrans;

		return false;
	}

	if (cipher == NULL)
	{
		ERROR_MSG("Failed to create the encryption token");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		delete encTrans;

		return false;
	}

	return true;
}

bool CPPSymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptUpdate(data, encryptedData))
	{
		delete cipher;
		cipher = NULL;

		return false;
	}

	// Put data
	try
	{
		if (data.size() > 0)
			cipher->Put(data.const_byte_str(), data.size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to write to the encipher token");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		delete cipher;
		cipher = NULL;

		return false;
	}

	// Get encrypted data
	encryptedData.resize(data.size() + getBlockSize() - 1);
	int outLen = encryptedData.size();
	try
	{
		outLen = cipher->Get(&encryptedData[0], outLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to encrypt the data");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		delete cipher;
		cipher = NULL;

		return false;
	}

	// Resize the output block
	encryptedData.resize(outLen);

	return true;
}

bool CPPSymmetricAlgorithm::encryptFinal(ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptFinal(encryptedData))
	{
		delete cipher;
		cipher = NULL;

		return false;
	}

	// Get final encrypted data
	encryptedData.resize(getBlockSize());
	int outLen = encryptedData.size();
	try
	{
		cipher->MessageEnd();
		outLen = cipher->Get(&encryptedData[0], outLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to encrypt the data");

		delete cipher;
		cipher = NULL;

		return false;
	}

	// Clean up
	delete cipher;
	cipher = NULL;

	// Resize the output block
	encryptedData.resize(outLen);

	return true;
}

// Decipher functions
bool CPPSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString() */, bool padding /* = true */)
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

	// Determine the decryptor
	bool reversenc = false;
	if (!mode.compare("ofb") || !mode.compare("cfb"))
	{
		reversenc = true;
	}
	CryptoPP::BlockCipher* dec = getCipher(reversenc);

	if (dec == NULL)
	{
		ERROR_MSG("Invalid decryptor");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Set the padding mode (PCKS7 or NoPadding)
	CryptoPP::StreamTransformationFilter::BlockPaddingScheme paddingScheme = CryptoPP::StreamTransformationFilter::NO_PADDING;
	if (padding)
	{
		paddingScheme = CryptoPP::StreamTransformationFilter::PKCS_PADDING;
	}

	CryptoPP::StreamTransformation* decTrans = NULL;

	try
	{
		if (!mode.compare("cbc"))
		{
			decTrans = new CryptoPP::CBC_Mode_ExternalCipher::Decryption(*dec, IV.const_byte_str());
		}
		else if (!mode.compare("ecb"))
		{
			decTrans = new CryptoPP::ECB_Mode_ExternalCipher::Decryption(*dec);
		}
		else if (!mode.compare("ofb"))
		{
			decTrans = new CryptoPP::OFB_Mode_ExternalCipher::Decryption(*dec, IV.const_byte_str());
		}
		else if (!mode.compare("cfb"))
		{
			decTrans = new CryptoPP::CFB_Mode_ExternalCipher::Decryption(*dec, IV.const_byte_str());
		}
		else
		{
			ERROR_MSG("Invalid cipher mode %s", mode.c_str());
		}
	}
	catch (...)
	{
		ERROR_MSG("Failed to create the decryption token");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	if (decTrans == NULL)
	{
		ERROR_MSG("Failed to create the decryption token");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	try
	{
		cipher = new CryptoPP::StreamTransformationFilter(*decTrans, NULL, paddingScheme);
	}
	catch (...)
	{
		ERROR_MSG("Failed to create the decryption token");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		delete decTrans;

		return false;
	}

	if (cipher == NULL)
	{
		ERROR_MSG("Failed to create the decryption token");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		delete decTrans;

		return false;
	}

	return true;
}

bool CPPSymmetricAlgorithm::decryptUpdate(const ByteString& encryptedData, ByteString& data)
{
	if (!SymmetricAlgorithm::decryptUpdate(encryptedData, data))
	{
		delete cipher;
		cipher = NULL;

		return false;
	}

	// Put data
	try
	{
		if (encryptedData.size() > 0)
			cipher->Put(encryptedData.const_byte_str(), encryptedData.size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to write to the decipher token");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		delete cipher;
		cipher = NULL;

		return false;
	}

	// Get clear data
	data.resize(encryptedData.size() + getBlockSize() - 1);
	int outLen = data.size();
	try
	{
		outLen = cipher->Get(&data[0], outLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to decrypt the data");

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		delete cipher;
		cipher = NULL;

		return false;
	}

	// Resize the output block
	data.resize(outLen);

	return true;
}

bool CPPSymmetricAlgorithm::decryptFinal(ByteString& data)
{
	if (!SymmetricAlgorithm::decryptFinal(data))
	{
		delete cipher;
		cipher = NULL;

		return false;
	}

	// Get final cleartext data
	data.resize(getBlockSize());
	int outLen = data.size();
	try
	{
		cipher->MessageEnd();
		outLen = cipher->Get(&data[0], outLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to decrypt the data");

		delete cipher;
		cipher = NULL;

		return false;
	}

	// Clean up
	delete cipher;
	cipher = NULL;

	// Resize the output block
	data.resize(outLen);

	return true;
}

