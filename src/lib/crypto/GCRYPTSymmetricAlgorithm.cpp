/*
 * Copyright (c) 2010 SURFnet bv
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
 GCRYPTSymmetricAlgorithm.cpp

 libgcrypt symmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "GCRYPTSymmetricAlgorithm.h"

// Constructor
GCRYPTSymmetricAlgorithm::GCRYPTSymmetricAlgorithm()
{
	cipherHd = NULL;
	buffer = NULL;
	final = NULL;
}

// Destructor
GCRYPTSymmetricAlgorithm::~GCRYPTSymmetricAlgorithm()
{
	if (cipherHd != NULL)
	{
		gcry_cipher_close(cipherHd);
	}
	delete buffer;
	delete final;
}

// Encryption functions
bool GCRYPTSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString()*/, bool padding /* = true */)
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

	// Determine the cipher class and mode
	gcry_cipher_algos cipher = getCipher();

	if (cipher == GCRY_CIPHER_NONE)
	{
		ERROR_MSG("Failed to initialise encrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Determine the cipher mode
	gcry_cipher_modes cipherMode;
	if (!mode.compare("cbc"))
	{
		cipherMode = GCRY_CIPHER_MODE_CBC;
	}
	else if (!mode.compare("ecb"))
	{
		cipherMode = GCRY_CIPHER_MODE_ECB;
	}
	else if(!mode.compare("ofb"))
	{
		cipherMode = GCRY_CIPHER_MODE_OFB;
		padding = false;
	}
	else if(!mode.compare("cfb"))
	{
		cipherMode = GCRY_CIPHER_MODE_CFB;
		padding = false;
	}
	else
	{
		ERROR_MSG("Invalid cipher mode %s", mode.c_str());

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	gcry_error_t rv = gcry_cipher_open(&cipherHd, cipher, cipherMode, 0);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("Failed to open encrypt operation");

		cipherHd = NULL;

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	ByteString keyData = currentKey->getKeyBits();
	if ((cipher == GCRY_CIPHER_3DES) && (currentKey->getBitLen() == 112))
	{
		keyData += keyData.substr(0, 8);
	}

	rv = gcry_cipher_setkey(cipherHd, keyData.const_byte_str(), keyData.size());
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("Failed to set the cipher key");

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	rv = gcry_cipher_setiv(cipherHd, iv.const_byte_str(), iv.size());
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("Failed to set the init vector");

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Create an align/padding buffer if needed
	if (padding)
	{
		buffer = new ByteString();
	}

	return true;
}

bool GCRYPTSymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptUpdate(data, encryptedData))
	{
		if (cipherHd != NULL)
		{
			gcry_cipher_close(cipherHd);
			cipherHd = NULL;
			delete buffer;
			buffer = NULL;
		}

		return false;
	}

	// Manage alignment
	ByteString in;
	if (buffer == NULL)
	{
		in = data;
	}
	else if ((buffer->size() == 0) && ((data.size() % getBlockSize()) == 0))
	{
		in = data;
	}
	else
	{
		in = *buffer + data;
		size_t n = (in.size() / getBlockSize()) * getBlockSize();
		buffer->resize(in.size() - n);
		memcpy(buffer->byte_str(), in.const_byte_str() + n, buffer->size());
		in.resize(n);
	}
	encryptedData.resize(in.size());

	if (in.size() == 0)
	{
		return true;
	}

	gcry_error_t rv = gcry_cipher_encrypt(cipherHd, &encryptedData[0], encryptedData.size(), in.const_byte_str(), in.size());
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("encrypt() failed");

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;
		delete buffer;
		buffer = NULL;

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTSymmetricAlgorithm::encryptFinal(ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptFinal(encryptedData))
	{
		if (cipherHd != NULL)
		{
			gcry_cipher_close(cipherHd);
			cipherHd = NULL;
			delete buffer;
			buffer = NULL;
		}

		return false;
	}

	// Manage padding
	if (buffer == NULL)
	{
		encryptedData.resize(0);

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;
		delete buffer;
		buffer = NULL;

		return true;
	}
	int n = getBlockSize() - buffer->size();
	ByteString in;
	in.resize(getBlockSize());
	memcpy(&in[0], buffer->const_byte_str(), buffer->size());
	memset(&in[buffer->size()], (unsigned char)n, (size_t)n);
	encryptedData.resize(in.size());

	gcry_error_t rv = gcry_cipher_encrypt(cipherHd, &encryptedData[0], encryptedData.size(), in.const_byte_str(), in.size());
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("final encrypt() failed");

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;
		delete buffer;
		buffer = NULL;

		return false;
	}

	gcry_cipher_close(cipherHd);
	cipherHd = NULL;
	delete buffer;
	buffer = NULL;

	return true;
}

// Decryption functions
bool GCRYPTSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const std::string mode /* = "cbc" */, const ByteString& IV /* = ByteString()*/, bool padding /* = true */)
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

	// Determine the cipher class and mode
	gcry_cipher_algos cipher = getCipher();

	if (cipher == GCRY_CIPHER_NONE)
	{
		ERROR_MSG("Failed to initialise decrypt operation");

		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);

		return false;
	}

	// Determine the cipher mode
	gcry_cipher_modes cipherMode;
	if (!mode.compare("cbc"))
	{
		cipherMode = GCRY_CIPHER_MODE_CBC;
	}
	else if (!mode.compare("ecb"))
	{
		cipherMode = GCRY_CIPHER_MODE_ECB;
	}
	else if(!mode.compare("ofb"))
	{
		cipherMode = GCRY_CIPHER_MODE_OFB;
		padding = false;
	}
	else if(!mode.compare("cfb"))
	{
		cipherMode = GCRY_CIPHER_MODE_CFB;
		padding = false;
	}
	else
	{
		ERROR_MSG("Invalid cipher mode %s", mode.c_str());

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	gcry_error_t rv = gcry_cipher_open(&cipherHd, cipher, cipherMode, 0);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("Failed to open decrypt operation");

		cipherHd = NULL;

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	ByteString keyData = currentKey->getKeyBits();
	if ((cipher == GCRY_CIPHER_3DES) && (currentKey->getBitLen() == 112))
	{
		keyData += keyData.substr(0, 8);
	}

	rv = gcry_cipher_setkey(cipherHd, keyData.const_byte_str(), keyData.size());
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("Failed to set the cipher key");

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	rv = gcry_cipher_setiv(cipherHd, iv.const_byte_str(), iv.size());
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("Failed to set the init vector");

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Create align/padding buffers if needed
	if (padding)
	{
		buffer = new ByteString();
		final = new ByteString();
	}

	return true;
}

bool GCRYPTSymmetricAlgorithm::decryptUpdate(const ByteString& encryptedData, ByteString& data)
{
	if (!SymmetricAlgorithm::decryptUpdate(encryptedData, data))
	{
		if (cipherHd != NULL)
		{
			gcry_cipher_close(cipherHd);
			cipherHd = NULL;
			delete buffer;
			buffer = NULL;
			delete final;
			final = NULL;
		}

		return false;
	}

	// Manage alignment
	ByteString in;
	ByteString out;
	if (buffer == NULL)
	{
		in = encryptedData;
	}
	else if ((buffer->size() == 0) && ((encryptedData.size() % getBlockSize()) == 0))
	{
		in = encryptedData;
	}
	else
	{
		in = *buffer + encryptedData;
		size_t n = (in.size() / getBlockSize()) * getBlockSize();
		buffer->resize(in.size() - n);
		memcpy(buffer->byte_str(), in.const_byte_str() + n, buffer->size());
		in.resize(n);
	}
	out.resize(in.size());

	if (in.size() == 0)
	{
		return true;
	}

	gcry_error_t rv = gcry_cipher_decrypt(cipherHd, &out[0], out.size(), in.const_byte_str(), in.size());
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("decrypt() failed");

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;
		delete buffer;
		buffer = NULL;
		delete final;
		final = NULL;

		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);

		return false;
	}

	// Manage padding
	if (buffer == NULL)
	{
		data = out;
	}
	else
	{
		// 
		if (final->size() != 0)
		{
			data = *final + out;
			final->resize(0);
		}
		else
		{
			data = out;
		}
		if (buffer->size() == 0)
		{
			final->resize(getBlockSize());
			size_t n = data.size() - getBlockSize();
			memcpy(final->byte_str(), data.const_byte_str() + n, final->size());
			data.resize(n);
		}
	}

	return true;
}

bool GCRYPTSymmetricAlgorithm::decryptFinal(ByteString& data)
{
	if (!SymmetricAlgorithm::decryptFinal(data))
	{
		if (cipherHd != NULL)
		{
			gcry_cipher_close(cipherHd);
			cipherHd = NULL;
			delete buffer;
			buffer = NULL;
			delete final;
			final = NULL;
		}

		return false;
	}

	// Manage padding
	if (buffer == NULL)
	{
		data.resize(0);

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;
		delete buffer;
		buffer = NULL;

		return true;
	}

	// Sanity
	if ((buffer->size() != 0) || (final->size() == 0))
	{
		ERROR_MSG("misaligned padded final decrypt");

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;
		delete buffer;
		buffer = NULL;
		delete final;
		final = NULL;

		return false;
	}
		
	data = *final;

	unsigned n = data[getBlockSize() - 1];
	bool badFinal = false;
	badFinal = badFinal || (n == 0) || (n > getBlockSize());
	if (!badFinal)
	{
		for (unsigned i = 1; i <= n; ++i)
		{
			badFinal = badFinal || (data[getBlockSize() - i] != n);
		}
	}
	if (badFinal)
	{
		ERROR_MSG("bad final block");

		gcry_cipher_close(cipherHd);
		cipherHd = NULL;
		delete buffer;
		buffer = NULL;
		delete final;
		final = NULL;

		return false;
	}

	data.resize(getBlockSize() - n);

	gcry_cipher_close(cipherHd);
	cipherHd = NULL;
	delete buffer;
	buffer = NULL;
	delete final;
	final = NULL;

	return true;
}

