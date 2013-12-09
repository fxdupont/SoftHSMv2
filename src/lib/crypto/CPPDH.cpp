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
 CPPDH.cpp

 Crypto++ Diffie-Hellman asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "CPPDH.h"
#include "CPPRNG.h"
#include "CPPCryptoFactory.h"
#include "DHParameters.h"
#include "CPPDHKeyPair.h"
#include "CPPUtil.h"
#include <algorithm>
#include <cryptopp/dh.h>

// Return signing function
CryptoPP::PK_Signer* CPPDH::getSigner() const
{
	ERROR_MSG("DH does not support signing");

	return NULL;
}

// Return verifying function
CryptoPP::PK_Verifier* CPPDH::getVerifier() const
{
	ERROR_MSG("DH does not support verifying");

	return NULL;
}

// Encryption/Decryption functions
CryptoPP::PK_Encryptor* CPPDH::getEncryptor() const
{
	ERROR_MSG("DH does not support encryption");

	return NULL;
}

CryptoPP::PK_Decryptor* CPPDH::getDecryptor() const
{
	ERROR_MSG("DH does not support decryption");

	return NULL;
}

// Key factory
bool CPPDH::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(DHParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for DH key generation");

		return false;
	}

	DHParameters* params = (DHParameters*) parameters;

	// Get the domain
	CryptoPP::DH* dh = NULL;
	try
	{
		dh = new CryptoPP::DH(CPPUtil::byteString2Integer(params->getP()),
				      CPPUtil::byteString2Integer(params->getG()));
	}
	catch (...)
	{
		ERROR_MSG("Failed to get Crypto++ DH domain");

		return false;
	}

	// Create an asymmetric key-pair object to return
	CPPDHKeyPair* kp = new CPPDHKeyPair();

	((CPPDHPrivateKey*) kp->getPrivateKey())->setP(params->getP());
	((CPPDHPrivateKey*) kp->getPrivateKey())->setG(params->getG());
	((CPPDHPublicKey*) kp->getPublicKey())->setP(params->getP());
	((CPPDHPublicKey*) kp->getPublicKey())->setG(params->getG());

	// Generate the key-pair
	CPPRNG* rng = (CPPRNG*)CPPCryptoFactory::i()->getRNG();
	ByteString x;
	x.resize(dh->PrivateKeyLength());
	ByteString y;
	y.resize(dh->PublicKeyLength());
	try
	{
		dh->GenerateKeyPair(*rng->getRNG(), &x[0], &y[0]);
	}
	catch (...)
	{
		ERROR_MSG("Failed to get Crypto++ DH keys");

		delete dh;
		delete kp;

		return false;
	}

	((CPPDHPrivateKey*) kp->getPrivateKey())->setX(x);
	((CPPDHPublicKey*) kp->getPublicKey())->setY(y);

	*ppKeyPair = kp;

	// Release the domain
	delete dh;

	return true;
}

bool CPPDH::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Get the domain
	CryptoPP::DH* dh = NULL;
	try
	{
		dh = new CryptoPP::DH(CPPUtil::byteString2Integer(((CPPDHPrivateKey*) privateKey)->getP()),
				      CPPUtil::byteString2Integer(((CPPDHPrivateKey*) privateKey)->getG()));
	}
	catch (...)
	{
		ERROR_MSG("DH key generation failed");

		return false;
	}

	// Get keys
	const ByteString pub = ((CPPDHPublicKey*) publicKey)->getY();
	const ByteString priv = ((CPPDHPrivateKey*) privateKey)->getX();

	// Derive the secret
	ByteString secret;
	secret.resize(dh->AgreedValueLength());
	if (!dh->Agree(&secret[0], priv.const_byte_str(), pub.const_byte_str()))
	{
		ERROR_MSG("Crypto++ DH key agreement failed");

		delete dh;

		return false;
	}

	delete dh;

	*ppSymmetricKey = new SymmetricKey(secret.size() * 8);
	if (*ppSymmetricKey == NULL)
	{
		ERROR_MSG("Can't create DH secret");

		return false;
	}
	if (!(*ppSymmetricKey)->setKeyBits(secret))
	{
		delete *ppSymmetricKey;
		*ppSymmetricKey = NULL;

		return false;
	}

	return true;
}

unsigned long CPPDH::getMinKeySize()
{
	return 512;
}

unsigned long CPPDH::getMaxKeySize()
{
	return 4096;
}

bool CPPDH::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* /*rng = NULL*/)
{
	if ((ppParams == NULL) || (parameters == NULL))
	{
		return false;
	}

	size_t bitLen = (size_t) parameters;

	if (bitLen < getMinKeySize() || bitLen > getMaxKeySize())
	{
		ERROR_MSG("This DH key size is not supported"); 

		return false;
	}

	CryptoPP::DH* dh = NULL;
	try
	{
		CPPRNG* rng = (CPPRNG*)CPPCryptoFactory::i()->getRNG();
		dh = new CryptoPP::DH(*rng->getRNG(), bitLen);
	}
	catch (...)
	{
		ERROR_MSG("Failed to generate %d bit DH parameters", bitLen);

		return false;
	}

	// Store the DH parameters
	DHParameters* params = new DHParameters();

	ByteString p = CPPUtil::Integer2ByteString(dh->GetGroupParameters().GetModulus());
	params->setP(p);
	ByteString g = CPPUtil::Integer2ByteString(dh->GetGroupParameters().GetSubgroupGenerator());
	params->setG(g);

	*ppParams = params;

	delete dh;

	return true;
}

bool CPPDH::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	CPPDHKeyPair* kp = new CPPDHKeyPair();

	bool rv = true;

	if (!((DHPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((DHPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool CPPDH::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	CPPDHPublicKey* pub = new CPPDHPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool CPPDH::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	CPPDHPrivateKey* priv = new CPPDHPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* CPPDH::newPublicKey()
{
	return (PublicKey*) new CPPDHPublicKey();
}

PrivateKey* CPPDH::newPrivateKey()
{
	return (PrivateKey*) new CPPDHPrivateKey();
}
	
AsymmetricParameters* CPPDH::newParameters()
{
	return (AsymmetricParameters*) new DHParameters();
}

bool CPPDH::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	DHParameters* params = new DHParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}

