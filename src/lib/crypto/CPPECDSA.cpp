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
 CPPECDSA.cpp

 Crypto++ ECDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "CPPECDSA.h"
#include "CPPECPublicKey.h"
#include "CPPECPrivateKey.h"
#include "CPPRNG.h"
#include "CPPCryptoFactory.h"
#include "CPPUtil.h"
#include <algorithm>
#include <iostream>

// Signing functions
bool CPPECDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		    ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("ecdsa"))
	{
		ERROR_MSG("Raw ECDSA is not supported");

		return false;
	}
	else
        {
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism);
        }
}

// Verification functions
bool CPPECDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		      const ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("ecdsa"))
	{
		ERROR_MSG("Raw ECDSA is not supported");

		return false;
	}
        else
        {
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism);
	}
}

// Return signing function
CryptoPP::PK_Signer* CPPECDSA::getSigner() const
{
	// Check if the private key is the right type
	if (!currentPrivateKey->isOfType(CPPECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return NULL;
	}

        CPPECPrivateKey* pk = (CPPECPrivateKey*) currentPrivateKey;

	CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>* cryptoppKey = pk->getCPPKey();

        if (!cryptoppKey)
        {
		ERROR_MSG("Could not get the Crypto++ private key");

		return NULL;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(currentMechanism.size());
	std::transform(currentMechanism.begin(), currentMechanism.end(), lowerMechanism.begin(), tolower);

	CryptoPP::PK_Signer* signer = NULL;
	try
	{       
		if (!lowerMechanism.compare("ecdsa-sha1"))
		{
			signer = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("ecdsa-sha224"))
		{
			signer = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA224>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("ecdsa-sha256"))
		{
			signer = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("ecdsa-sha384"))
		{
			signer = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("ecdsa-sha512"))
		{
			signer = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::Signer(*cryptoppKey);
		}
		else
		{
			ERROR_MSG("Invalid mechanism supplied (%s)", currentMechanism.c_str());

			return NULL;
		}
	}
	catch (...)
	{
		ERROR_MSG("Could not create the signer token");

		return NULL;
	}

	if (signer == NULL)
	{
		ERROR_MSG("Could not create the signer token");

		return NULL;
	}

	return signer;
}

// Return verifying function
CryptoPP::PK_Verifier* CPPECDSA::getVerifier() const
{
	// Check if the public key is the right type
	if (!currentPublicKey->isOfType(CPPECPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return NULL;
	}

        CPPECPublicKey* pk = (CPPECPublicKey*) currentPublicKey;
	CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>* cryptoppKey = pk->getCPPKey();

        if (!cryptoppKey)
        {
		ERROR_MSG("Could not get the Crypto++ public key");

		return NULL;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(currentMechanism.size());
	std::transform(currentMechanism.begin(), currentMechanism.end(), lowerMechanism.begin(), tolower);

	CryptoPP::PK_Verifier* verifier = NULL;
	try
	{       

		if (!lowerMechanism.compare("ecdsa-sha1"))
		{
			verifier = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("ecdsa-sha224"))
		{
			verifier = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA224>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("ecdsa-sha256"))
		{
			verifier = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("ecdsa-sha384"))
		{
			verifier = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("ecdsa-sha512"))
		{
			verifier = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::Verifier(*cryptoppKey);
		}
		else
		{
			ERROR_MSG("Invalid mechanism supplied (%s)", currentMechanism.c_str());

			return NULL;
		}
	}
	catch (...)
	{
		ERROR_MSG("Could not create the verifier token");

		return NULL;
	}

	if (verifier == NULL)
	{
		ERROR_MSG("Could not create the verifier token");

		return NULL;
	}

	return verifier;
}
#endif
