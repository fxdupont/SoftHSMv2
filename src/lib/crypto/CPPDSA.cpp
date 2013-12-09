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
 CPPDSA.cpp

 Crypto++ DSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "CPPDSA.h"
#include "CPPRNG.h"
#include "CryptoFactory.h"
#include "CPPCryptoFactory.h"
#include "DSAParameters.h"
#include "CPPDSAKeyPair.h"
#include "CPPUtil.h"
#include <algorithm>
#include <iostream>
#include <cryptopp/dsa.h>

// Signing functions
bool CPPDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		  ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("dsa"))
	{
		ERROR_MSG("Raw DSA is not supported");

		return false;
	}
	else
        {
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism);
        }
}

// Verification functions
bool CPPDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		      const ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("dsa"))
	{
		ERROR_MSG("Raw DSA is not supported");

		return false;
	}
        else
        {
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism);
	}
}

// Return signing function
CryptoPP::PK_Signer* CPPDSA::getSigner() const
{
	// Check if the private key is the right type
	if (!currentPrivateKey->isOfType(CPPDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return NULL;
	}

        CPPDSAPrivateKey* pk = (CPPDSAPrivateKey*) currentPrivateKey;
	CryptoPP::DL_Keys_DSA::PrivateKey* cryptoppKey = pk->getCPPKey();

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
		if (!lowerMechanism.compare("dsa-sha1"))
		{
			signer = new CryptoPP::DSA2<CryptoPP::SHA1>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("dsa-sha224"))
		{
			signer = new CryptoPP::DSA2<CryptoPP::SHA224>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("dsa-sha256"))
		{
			signer = new CryptoPP::DSA2<CryptoPP::SHA256>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("dsa-sha384"))
		{
			signer = new CryptoPP::DSA2<CryptoPP::SHA384>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("dsa-sha512"))
		{
			signer = new CryptoPP::DSA2<CryptoPP::SHA512>::Signer(*cryptoppKey);
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
CryptoPP::PK_Verifier* CPPDSA::getVerifier() const
{
	// Check if the public key is the right type
	if (!currentPublicKey->isOfType(CPPDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return NULL;
	}

        CPPDSAPublicKey* pk = (CPPDSAPublicKey*) currentPublicKey;
	CryptoPP::DL_Keys_DSA::PublicKey* cryptoppKey = pk->getCPPKey();

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

		if (!lowerMechanism.compare("dsa-sha1"))
		{
			verifier = new CryptoPP::DSA2<CryptoPP::SHA1>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("dsa-sha224"))
		{
			verifier = new CryptoPP::DSA2<CryptoPP::SHA224>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("dsa-sha256"))
		{
			verifier = new CryptoPP::DSA2<CryptoPP::SHA256>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("dsa-sha384"))
		{
			verifier = new CryptoPP::DSA2<CryptoPP::SHA384>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("dsa-sha512"))
		{
			verifier = new CryptoPP::DSA2<CryptoPP::SHA512>::Verifier(*cryptoppKey);
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

// Encryption/Decryption functions
CryptoPP::PK_Encryptor* CPPDSA::getEncryptor() const
{
	ERROR_MSG("DSA does not support encryption");

	return NULL;
}

CryptoPP::PK_Decryptor* CPPDSA::getDecryptor() const
{
	ERROR_MSG("DSA does not support decryption");

	return NULL;
}

// Key factory
bool CPPDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(DSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for DSA key generation");

		return false;
	}

	DSAParameters* params = (DSAParameters*) parameters;

	// Generate the key-pair
	CryptoPP::DL_Keys_DSA::PrivateKey* dsa = new CryptoPP::DL_Keys_DSA::PrivateKey();
	try
	{
		CPPRNG* rng = (CPPRNG*)CPPCryptoFactory::i()->getRNG();
		dsa->GenerateRandom(*rng->getRNG(),
			CryptoPP::MakeParameters
			(CryptoPP::Name::Modulus(), CPPUtil::byteString2Integer(params->getP()))
			(CryptoPP::Name::SubgroupOrder(), CPPUtil::byteString2Integer(params->getQ()))
			(CryptoPP::Name::SubgroupGenerator(), CPPUtil::byteString2Integer(params->getG())));
	}
	catch (...)
	{
		ERROR_MSG("DSA key generation failed");

		delete dsa;

		return false;
	}

	// Create an asymmetric key-pair object to return
	CPPDSAKeyPair* kp = new CPPDSAKeyPair();

	((CPPDSAPrivateKey*) kp->getPrivateKey())->setFromCPP(dsa);
	CryptoPP::DL_Keys_DSA::PublicKey* pubdsa = new CryptoPP::DL_Keys_DSA::PublicKey();
	pubdsa->AssignFrom(*dsa);
	((CPPDSAPublicKey*) kp->getPublicKey())->setFromCPP(pubdsa);

	*ppKeyPair = kp;

	// Release the key
	delete dsa;
	delete pubdsa;

	return true;
}

// and DSA::PRIME_LENGTH_MULTIPLE == 1024
unsigned long CPPDSA::getMinKeySize()
{
	// DSA::MIN_PRIME_LENGTH
	return 1024;
}

unsigned long CPPDSA::getMaxKeySize()
{
	// DSA::MAX_PRIME_LENGTH
	return 3072;
}

bool CPPDSA::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* /*rng = NULL*/)
{
	if ((ppParams == NULL) || (parameters == NULL))
	{
		return false;
	}

	size_t bitLen = (size_t) parameters;

	if (bitLen < getMinKeySize() || bitLen > getMaxKeySize())
	{
		ERROR_MSG("This DSA key size is not supported"); 

		return false;
	}
	CryptoPP::DL_GroupParameters_DSA* group = new CryptoPP::DL_GroupParameters_DSA();
	try
	{
		CPPRNG* rng = (CPPRNG*)CPPCryptoFactory::i()->getRNG();
		group->GenerateRandomWithKeySize(*rng->getRNG(), bitLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to generate %d bit DSA parameters", bitLen);

		delete group;

		return false;
	}

	// Store the DSA parameters
	DSAParameters* params = new DSAParameters();

	ByteString p = CPPUtil::Integer2ByteString(group->GetModulus());
	params->setP(p);
	ByteString q = CPPUtil::Integer2ByteString(group->GetSubgroupOrder());
	params->setQ(q);
	ByteString g = CPPUtil::Integer2ByteString(group->GetSubgroupGenerator());
	params->setG(g);

	*ppParams = params;

	delete group;

	return true;
}

bool CPPDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	CPPDSAKeyPair* kp = new CPPDSAKeyPair();

	bool rv = true;

	if (!((DSAPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((DSAPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
	{
		rv = false;
	}

	if (!rv)
	{
		delete kp;

		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool CPPDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	CPPDSAPublicKey* pub = new CPPDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool CPPDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	CPPDSAPrivateKey* priv = new CPPDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* CPPDSA::newPublicKey()
{
	return (PublicKey*) new CPPDSAPublicKey();
}

PrivateKey* CPPDSA::newPrivateKey()
{
	return (PrivateKey*) new CPPDSAPrivateKey();
}
	
AsymmetricParameters* CPPDSA::newParameters()
{
	return (AsymmetricParameters*) new DSAParameters();
}

bool CPPDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	DSAParameters* params = new DSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
