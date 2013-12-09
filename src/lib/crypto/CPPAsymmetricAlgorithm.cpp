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
 CPPAsymmetricAlgorithm.cpp

 Crypto++ asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "CPPAsymmetricAlgorithm.h"
#include "CPPCryptoFactory.h"
#include "CPPRNG.h"
#include <algorithm>

// Constructor
CPPAsymmetricAlgorithm::CPPAsymmetricAlgorithm()
{
	signer = NULL;
	verifier = NULL;
	encryptor = NULL;
	decryptor = NULL;
}

// Destructor
CPPAsymmetricAlgorithm::~CPPAsymmetricAlgorithm()
{
	delete signer;
	delete verifier;
	delete encryptor;
	delete decryptor;
}

// Signing functions
bool CPPAsymmetricAlgorithm::signInit(PrivateKey* privateKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism))
	{
		return false;
	}

	CryptoPP::PK_Signer* pk_signer = getSigner();
	if (pk_signer == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	CPPRNG* rng = (CPPRNG*)CPPCryptoFactory::i()->getRNG();
	signer = new CryptoPP::SignerFilter(*rng->getRNG(), *pk_signer);

	if (signer == NULL)
	{
		ERROR_MSG("Could not create the signer token");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	SignatureLength = pk_signer->SignatureLength();

	return true;
}

bool CPPAsymmetricAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	try
	{
		signer->Put(dataToSign.const_byte_str(), dataToSign.size());
	}
	catch (...)
	{
		ERROR_MSG("Could not add data to signer token");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		delete signer;
		signer = NULL;
		SignatureLength = 0;

		return false;
	}

	return true;
}

bool CPPAsymmetricAlgorithm::signFinal(ByteString& signature)
{
	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	// Perform the signature operation
	CryptoPP::SecByteBlock signResult(SignatureLength);
	int sigLen;
	try
	{
		signer->MessageEnd();
		sigLen = signer->Get(signResult.begin(), signResult.size());
	}
	catch (...)
	{
		ERROR_MSG("Could not sign the data");

		delete signer;
		signer = NULL;
		SignatureLength = 0;

		return false;
	}

	// Return the result
	signature.resize(sigLen);
	memcpy(&signature[0], signResult.begin(), signResult.size());

	delete signer;
	signer = NULL;
	SignatureLength = 0;

	return true;
}

// Verification functions
bool CPPAsymmetricAlgorithm::verifyInit(PublicKey* publicKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism))
	{
		return false;
	}


	CryptoPP::PK_Verifier* pk_verifier = getVerifier();
	if (pk_verifier == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	verifier = new CryptoPP::SignatureVerificationFilter(*pk_verifier, NULL, CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_END | CryptoPP::SignatureVerificationFilter::PUT_RESULT);

	if (verifier == NULL)
	{
		ERROR_MSG("Could not create the verifier token");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	SignatureLength = pk_verifier->SignatureLength();

	return true;
}

bool CPPAsymmetricAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	try
	{
		verifier->Put(originalData.const_byte_str(), originalData.size());
	}
	catch (...)
	{
		ERROR_MSG("Could not add data to the verifier token");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		delete verifier;
		verifier = NULL;
		SignatureLength = 0;

		return false;
	}

	return true;
}

bool CPPAsymmetricAlgorithm::verifyFinal(const ByteString& signature)
{
	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	// Check length
	if (signature.size() != SignatureLength)
	{
		return false;
	}

	// Perform the verify operation
	bool verResult;
	try
	{
		verifier->Put(signature.const_byte_str(), signature.size());
		verifier->MessageEnd();
		verifier->Get((unsigned char*)&verResult, sizeof(verResult));
	}
	catch (...)
	{
		ERROR_MSG("Could not check the signature");

		delete verifier;
		verifier = NULL;
		SignatureLength = 0;

		return false;
	}

	delete verifier;
	verifier = NULL;
	SignatureLength = 0;

	return verResult != false;
}

// Encryption functions
bool CPPAsymmetricAlgorithm::encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const std::string padding)
{
	currentEncryptionKey = publicKey;
	currentPadding = padding;

	CryptoPP::PK_Encryptor* enc = getEncryptor();
	if (enc == NULL)
	{
		currentEncryptionKey = NULL;
		currentPadding = "";

		return false;
	}

	CPPRNG* rng = (CPPRNG*)CPPCryptoFactory::i()->getRNG();
	encryptor = new CryptoPP::PK_EncryptorFilter(*rng->getRNG(), *enc);

	if (encryptor == NULL)
	{
		ERROR_MSG("Could not create the encryptor token");

		currentEncryptionKey = NULL;
		currentPadding = "";

		return false;
	}

	// Perform the encryption operation
	try
	{
		encryptor->Put(data.const_byte_str(), data.size());
		encryptor->MessageEnd();
		int outLen = encryptor->MaxRetrievable();
		encryptedData.resize(outLen);
		outLen = encryptor->Get(&encryptedData[0], encryptedData.size());
		encryptedData.resize(outLen);
	}
	catch (...)
	{
		ERROR_MSG("Could not encrypt the data");

		delete encryptor;
		encryptor = NULL;
		currentEncryptionKey = NULL;
		currentPadding = "";

		return false;
	}

	delete encryptor;
	encryptor = NULL;
	currentEncryptionKey = NULL;
	currentPadding = "";

	return true;
}

// Decryption functions
bool CPPAsymmetricAlgorithm::decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const std::string padding)
{
	currentDecryptionKey = privateKey;
	currentPadding = padding;

	CryptoPP::PK_Decryptor* dec = getDecryptor();
	if (dec == NULL)
	{
		currentDecryptionKey = NULL;
		currentPadding = padding;
	}

	CPPRNG* rng = (CPPRNG*)CPPCryptoFactory::i()->getRNG();
	decryptor = new CryptoPP::PK_DecryptorFilter(*rng->getRNG(), *dec);

	if (decryptor == NULL)
	{
		ERROR_MSG("Could not create the decryptor token");

		currentDecryptionKey = NULL;
		currentPadding = padding;

		return false;
	}

	// Perform the decryption operation
	try
	{
		decryptor->Put(encryptedData.const_byte_str(), encryptedData.size());
		decryptor->MessageEnd();
		int outLen = decryptor->MaxRetrievable();
		data.resize(outLen);
		outLen = decryptor->Get(&data[0], data.size());
		data.resize(outLen);
	}
	catch (...)
	{
		ERROR_MSG("Could not decrypt the data");

		delete decryptor;
		decryptor = NULL;
		currentDecryptionKey = NULL;
		currentPadding = padding;

		return false;
	}

	delete decryptor;
	decryptor = NULL;
	currentDecryptionKey = NULL;
	currentPadding = padding;

	return true;
}
