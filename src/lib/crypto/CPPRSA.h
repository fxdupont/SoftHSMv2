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
 CPPRSA.h

 Crypto++ RSA asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CPPRSA_H
#define _SOFTHSM_V2_CPPRSA_H

#include "config.h"
#include "CPPAsymmetricAlgorithm.h"
#include <cryptopp/rsa.h>

class CPPRSA : public CPPAsymmetricAlgorithm
{
public:
	// Destructor
	virtual ~CPPRSA() { }

	// Signing function
	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const std::string mechanism);

	// Verification function
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const std::string mechanism);

	// Key factory
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL);
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData);
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData);
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData);
	virtual PublicKey* newPublicKey();
	virtual PrivateKey* newPrivateKey();
	virtual AsymmetricParameters* newParameters();

protected:
	// Return the right interface instances for the operations
	virtual CryptoPP::PK_Signer* getSigner() const;
	virtual CryptoPP::PK_Verifier* getVerifier() const;
	virtual CryptoPP::PK_Encryptor* getEncryptor() const;
	virtual CryptoPP::PK_Decryptor* getDecryptor() const;
};

#endif // !_SOFTHSM_V2_CPPRSA_H

