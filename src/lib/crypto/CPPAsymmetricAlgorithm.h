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
 CPPAsymmetricAlgorithm.h

 Crypto++ asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CPPAsymmetricAlgorithm_H
#define _SOFTHSM_V2_CPPAsymmetricAlgorithm_H

#include "config.h"
#include "AsymmetricAlgorithm.h"

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>

class CPPAsymmetricAlgorithm : public AsymmetricAlgorithm
{
public:
	// Constructor
	CPPAsymmetricAlgorithm();

	// Destructor
	virtual ~CPPAsymmetricAlgorithm();

	// Signing functions
	virtual bool signInit(PrivateKey* privateKey, const std::string mechanism);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verifyInit(PublicKey* publicKey, const std::string mechanism);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(const ByteString& signature);

	// Encryption functions
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const std::string padding);

	// Decryption functions
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const std::string padding);

protected:
	// Return the right interface instances for the operations
	virtual CryptoPP::PK_Signer* getSigner() const = 0;
	virtual CryptoPP::PK_Verifier* getVerifier() const = 0;
	virtual CryptoPP::PK_Encryptor* getEncryptor() const = 0;
	virtual CryptoPP::PK_Decryptor* getDecryptor() const = 0;

	// Encryption/Decryption keys
	PublicKey* currentEncryptionKey;
	PrivateKey* currentDecryptionKey;

private:
	// The current contexts
	CryptoPP::SignerFilter* signer;
	CryptoPP::SignatureVerificationFilter* verifier;
	CryptoPP::PK_EncryptorFilter* encryptor;
	CryptoPP::PK_DecryptorFilter* decryptor;

	// Cached length
	size_t SignatureLength;
};

#endif // !_SOFTHSM_V2_CPPASYMMETRICALGORITHM_H

