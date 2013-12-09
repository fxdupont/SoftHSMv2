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
 CPPRSA.cpp

 Crypto++ RSA asymmetric algorithm implementation
 *****************************************************************************/

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "config.h"
#include "log.h"
#include "CPPRSA.h"
#include "CPPRNG.h"
#include "CPPCryptoFactory.h"
#include "CPPRSAKeyPair.h"
#include "RSAParameters.h"
#include "CPPUtil.h"
#include <algorithm>
#include <cryptopp/md5.h>

// Signing functions
bool CPPRSA::sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("rsa-pkcs"))
	{
		ERROR_MSG("EMSA3(Raw) aka PKCS RSA is not supported");

		return false;
	}
	else if (!lowerMechanism.compare("rsa-raw"))
	{
		ERROR_MSG("Raw RSA is not supported");

		return false;
	}
	else
	{
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism);
	}
}
	
// Verification function
bool CPPRSA::verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("rsa-pkcs"))
	{
		ERROR_MSG("EMSA3(Raw) aka PKCS RSA is not supported");

		return false;
	}
	else if (!lowerMechanism.compare("rsa-raw"))
	{
		ERROR_MSG("Raw RSA is not supported");

		return false;
	}
	else
	{
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism);
	}
}

// Return signing function
CryptoPP::PK_Signer* CPPRSA::getSigner() const
{
	// Check if the private key is the right type
	if (!currentPrivateKey->isOfType(CPPRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return NULL;
	}

	CPPRSAPrivateKey* pk = (CPPRSAPrivateKey*) currentPrivateKey;
	CryptoPP::RSA::PrivateKey* cryptoppKey = pk->getCPPKey();

	if (cryptoppKey == NULL)
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
		if (!lowerMechanism.compare("rsa-md5-pkcs"))
		{
			signer = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::Weak1::MD5>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha1-pkcs"))
		{
			signer = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA1>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha224-pkcs"))
		{
			signer = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA224>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha256-pkcs"))
		{
			signer = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha384-pkcs"))
		{
			signer = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA384>::Signer(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha512-pkcs"))
		{
			signer = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA512>::Signer(*cryptoppKey);
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
CryptoPP::PK_Verifier* CPPRSA::getVerifier() const
{
	// Check if the public key is the right type
	if (!currentPublicKey->isOfType(CPPRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return NULL;
	}

	CPPRSAPublicKey* pk = (CPPRSAPublicKey*) currentPublicKey;
	CryptoPP::RSA::PublicKey* cryptoppKey = pk->getCPPKey();

	if (cryptoppKey == NULL)
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
		if (!lowerMechanism.compare("rsa-md5-pkcs"))
		{
			verifier = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::Weak1::MD5>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha1-pkcs"))
		{
			verifier = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA1>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha224-pkcs"))
		{
			verifier = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA224>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha256-pkcs"))
		{
			verifier = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha384-pkcs"))
		{
			verifier = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA384>::Verifier(*cryptoppKey);
		}
		else if (!lowerMechanism.compare("rsa-sha512-pkcs"))
		{
			verifier = new CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA512>::Verifier(*cryptoppKey);
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

// Return encryption function
CryptoPP::PK_Encryptor* CPPRSA::getEncryptor() const
{
	// Check if the public key is the right type
	if (!currentEncryptionKey->isOfType(CPPRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return NULL;
	}

	CPPRSAPublicKey* pk = (CPPRSAPublicKey*) currentEncryptionKey;
	CryptoPP::RSA::PublicKey* cryptoppKey = pk->getCPPKey();

	if (cryptoppKey == NULL)
	{
		ERROR_MSG("Could not get the Crypto++ public key");

		return NULL;
	}

	std::string lowerPadding;
	lowerPadding.resize(currentPadding.size());
	std::transform(currentPadding.begin(), currentPadding.end(), lowerPadding.begin(), tolower);

	CryptoPP::PK_Encryptor* encryptor = NULL;
	try
	{
		if (!lowerPadding.compare("rsa-pkcs"))
		{
			encryptor = new CryptoPP::RSAES<CryptoPP::PKCS1v15>::Encryptor(*cryptoppKey);
		}
		else if (!lowerPadding.compare("rsa-pkcs-oaep"))
		{
			encryptor = new CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA1> >::Encryptor(*cryptoppKey);
		}
		else
		{
			ERROR_MSG("Invalid padding mechanism supplied (%s)", currentPadding.c_str());

			return NULL;
		}
	}
	catch (...)
	{
		ERROR_MSG("Could not create the encryptor token");

		return NULL;
	}

	if (encryptor == NULL)
	{
		ERROR_MSG("Could not create the encryptor token");

		return NULL;
	}

	return encryptor;
}

// Return decryption function
CryptoPP::PK_Decryptor* CPPRSA::getDecryptor() const
{
	// Check if the private key is the right type
	if (!currentDecryptionKey->isOfType(CPPRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return NULL;
	}

	CPPRSAPrivateKey* pk = (CPPRSAPrivateKey*) currentDecryptionKey;
	CryptoPP::RSA::PrivateKey* cryptoppKey = pk->getCPPKey();

	if (cryptoppKey == NULL)
	{
		ERROR_MSG("Could not get the Crypto++ private key");

		return NULL;
	}

	std::string lowerPadding;
	lowerPadding.resize(currentPadding.size());
	std::transform(currentPadding.begin(), currentPadding.end(), lowerPadding.begin(), tolower);

	CryptoPP::PK_Decryptor* decryptor = NULL;
	try
	{
		if (!lowerPadding.compare("rsa-pkcs"))
		{
			decryptor = new CryptoPP::RSAES<CryptoPP::PKCS1v15>::Decryptor(*cryptoppKey);
		}
		else if (!lowerPadding.compare("rsa-pkcs-oaep"))
		{
			decryptor = new CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA1> >::Decryptor(*cryptoppKey);
		}
		else
		{
			ERROR_MSG("Invalid padding mechanism supplied (%s)", currentPadding.c_str());

			return NULL;
		}
	}
	catch (...)
	{
		ERROR_MSG("Could not create the decryptor token");

		return NULL;
	}

	if (decryptor == NULL)
	{
		ERROR_MSG("Could not create the decryptor token");

		return NULL;
	}

	return decryptor;
}

// Key factory
bool CPPRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(RSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for RSA key generation");

		return false;
	}

	RSAParameters* params = (RSAParameters*) parameters;

	if (params->getBitLength() < getMinKeySize() || params->getBitLength() > getMaxKeySize())
	{
		ERROR_MSG("This RSA key size is not supported");

		return false;
	}

	if (params->getBitLength() < 1024)
	{
		WARNING_MSG("Using an RSA key size < 1024 bits is not recommended");
	}

	// Retrieve the desired public exponent
	unsigned long e = params->getE().long_val();

	// Check the public exponent
	if ((e == 0) || (e % 2 != 1))
	{
		ERROR_MSG("Invalid RSA public exponent %d", e);

		return false;
	}

	// Generate the key-pair
	CryptoPP::RSA::PrivateKey* rsa = new CryptoPP::RSA::PrivateKey();
	try {
		CPPRNG* rng = (CPPRNG*)CPPCryptoFactory::i()->getRNG();
		rsa->Initialize(*rng->getRNG(),
				params->getBitLength(),
				CPPUtil::byteString2Integer(params->getE()));
	}
	catch(...)
	{
		ERROR_MSG("RSA key generation failed");

		delete rsa;

		return false;
	}

	// Create an asymmetric key-pair object to return
	CPPRSAKeyPair* kp = new CPPRSAKeyPair();

	((CPPRSAPrivateKey*) kp->getPrivateKey())->setFromCPP(rsa);
	CryptoPP::RSA::PublicKey* pubrsa = new CryptoPP::RSA::PublicKey(*rsa);
	((CPPRSAPublicKey*) kp->getPublicKey())->setFromCPP(pubrsa);

	*ppKeyPair = kp;

	// Release the key
	delete rsa;
	delete pubrsa;

	return true;
}

unsigned long CPPRSA::getMinKeySize()
{
	return 512;
}

unsigned long CPPRSA::getMaxKeySize()
{
	return 4096;
}

bool CPPRSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	CPPRSAKeyPair* kp = new CPPRSAKeyPair();

	bool rv = true;

	if (!((RSAPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((RSAPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool CPPRSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	CPPRSAPublicKey* pub = new CPPRSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool CPPRSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	CPPRSAPrivateKey* priv = new CPPRSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* CPPRSA::newPublicKey()
{
	return (PublicKey*) new CPPRSAPublicKey();
}

PrivateKey* CPPRSA::newPrivateKey()
{
	return (PrivateKey*) new CPPRSAPrivateKey();
}
	
AsymmetricParameters* CPPRSA::newParameters()
{
	return (AsymmetricParameters*) new RSAParameters();
}

