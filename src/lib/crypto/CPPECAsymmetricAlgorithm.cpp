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
 CPPEC.cpp

 Crypto++ elliptic curve asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "CPPECAsymmetricAlgorithm.h"
#include "CPPRNG.h"
#include "CPPCryptoFactory.h"
#include "ECParameters.h"
#include "CPPECKeyPair.h"
#include "CPPUtil.h"
#include <algorithm>
#include <iostream>

// Encryption/Decryption functions
CryptoPP::PK_Encryptor* CPPECAsymmetricAlgorithm::getEncryptor() const
{
	ERROR_MSG("ECC does not support encryption");

	return NULL;
}

CryptoPP::PK_Decryptor* CPPECAsymmetricAlgorithm::getDecryptor() const
{
	ERROR_MSG("ECC does not support decryption");

	return NULL;
}

// Key factory
bool CPPECAsymmetricAlgorithm::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for EC key generation");

		return false;
	}

	ECParameters* params = (ECParameters*) parameters;

	// Generate the key-pair
	CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>* ec = new CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>();
	try
	{
		CPPRNG* rng = (CPPRNG*)CPPCryptoFactory::i()->getRNG();
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> grp(CPPUtil::byteString2ECGroupOID(params->getEC()));
		grp.SetEncodeAsOID(true);
		ec->GenerateRandom(*rng->getRNG(), grp);
	}
	catch (...)
	{
		ERROR_MSG("EC key generation failed");

		delete ec;

		return false;
	}

	// Create an asymmetric key-pair object to return
	CPPECKeyPair* kp = new CPPECKeyPair();

	((CPPECPrivateKey*) kp->getPrivateKey())->setFromCPP(ec);
	CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>* pubec = new CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>();
	ec->MakePublicKey(*pubec);
	pubec->AccessGroupParameters().SetEncodeAsOID(true);
	((CPPECPublicKey*) kp->getPublicKey())->setFromCPP(pubec);

	*ppKeyPair = kp;

	// Release the key
	delete ec;
	delete pubec;

	return true;
}

unsigned long CPPECAsymmetricAlgorithm::getMinKeySize()
{
	// smallest ECP is secp112r1
	return 112;
}

unsigned long CPPECAsymmetricAlgorithm::getMaxKeySize()
{
	// biggest ECP is secp521r1
	return 521;
}

bool CPPECAsymmetricAlgorithm::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	CPPECKeyPair* kp = new CPPECKeyPair();

	bool rv = true;

	if (!((ECPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((ECPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool CPPECAsymmetricAlgorithm::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	CPPECPublicKey* pub = new CPPECPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool CPPECAsymmetricAlgorithm::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	CPPECPrivateKey* priv = new CPPECPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* CPPECAsymmetricAlgorithm::newPublicKey()
{
	return (PublicKey*) new CPPECPublicKey();
}

PrivateKey* CPPECAsymmetricAlgorithm::newPrivateKey()
{
	return (PrivateKey*) new CPPECPrivateKey();
}
	
AsymmetricParameters* CPPECAsymmetricAlgorithm::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool CPPECAsymmetricAlgorithm::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ECParameters* params = new ECParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
#endif
