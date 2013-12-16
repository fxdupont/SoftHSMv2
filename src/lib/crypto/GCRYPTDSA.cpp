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
 GCRYPTDSA.cpp

 libgcrypt DSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "GCRYPTDSA.h"
#include "CryptoFactory.h"
#include "DSAParameters.h"
#include "GCRYPTDSAKeyPair.h"
#include "GCRYPTUtil.h"
#include <algorithm>

// Constructor
GCRYPTDSA::GCRYPTDSA()
{
	hash = NULL;
}

// Destructor
GCRYPTDSA::~GCRYPTDSA()
{
	if (hash != NULL)
	{
		delete hash;
	}
}
	
// Signing functions
bool GCRYPTDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("dsa"))
	{

		// Separate implementation for DSA signing without hash computation

		// Check if the private key is the right type
		if (!privateKey->isOfType(GCRYPTDSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		GCRYPTDSAPrivateKey* pk = (GCRYPTDSAPrivateKey*) privateKey;
		gcry_sexp_t dsa = pk->getGCRYPTKey();

		// Perform the signature operation
		unsigned int sigLen = pk->getOutputLength();
		signature.resize(sigLen);
		memset(&signature[0], 0, sigLen);
		gcry_mpi_t dataMpi = GCRYPTUtil::byteString2mpi(dataToSign);
		gcry_sexp_t dataSexpr = NULL;
		gcry_error_t rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags raw) (value %M))", dataMpi);
		gcry_mpi_release(dataMpi);
		if (rv != GPG_ERR_NO_ERROR)
		{
			ERROR_MSG("failed to build data S-expr");

			return false;
		}
		gcry_sexp_t sigSexpr = NULL;
		rv = gcry_pk_sign(&sigSexpr, dataSexpr, dsa);
		gcry_sexp_release(dataSexpr);
		if (rv != GPG_ERR_NO_ERROR)
		{
			ERROR_MSG("failed to sign");

			return false;
		}
		if (sigSexpr == NULL)
			return false;
		// Store the 2 values with padding
		gcry_sexp_t rx = gcry_sexp_find_token(sigSexpr, "r", 0);
		gcry_sexp_t sx = gcry_sexp_find_token(sigSexpr, "s", 0);
		gcry_sexp_release(sigSexpr);
		if ((rx == NULL) || (sx == NULL))
		{
			ERROR_MSG("failed to parse signature");

			return false;
		}
		gcry_mpi_t ri = gcry_sexp_nth_mpi(rx, 1, GCRYMPI_FMT_USG);
		gcry_mpi_t si = gcry_sexp_nth_mpi(sx, 1, GCRYMPI_FMT_USG);
		gcry_sexp_release(rx);
		gcry_sexp_release(sx);
		if ((ri == NULL) || (si == NULL))
		{
			ERROR_MSG("failed to read signature");

			return false;
		}
		ByteString r = GCRYPTUtil::mpi2ByteString(ri);
		ByteString s = GCRYPTUtil::mpi2ByteString(si);
		gcry_mpi_release(ri);
		gcry_mpi_release(si);
		memcpy(&signature[sigLen / 2 - r.size()], r.const_byte_str(), r.size());
		memcpy(&signature[sigLen - s.size()], s.const_byte_str(), s.size());
		return true;
	}
	else
	{
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism);
	}
}

bool GCRYPTDSA::signInit(PrivateKey* privateKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(GCRYPTDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("dsa-sha1"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("dsa-sha224"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha224");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("dsa-sha256"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha256");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("dsa-sha384"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha384");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	if (!lowerMechanism.compare("dsa-sha512"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha512");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}

	if (hash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTDSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (!hash->hashUpdate(dataToSign))
	{
		delete hash;
		hash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTDSA::signFinal(ByteString& signature)
{	
	// Save necessary state before calling super class signFinal
	GCRYPTDSAPrivateKey* pk = (GCRYPTDSAPrivateKey*) currentPrivateKey;

	std::string lowerMechanism;
	lowerMechanism.resize(currentMechanism.size());
	std::transform(currentMechanism.begin(), currentMechanism.end(), lowerMechanism.begin(), tolower);

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString digest;

	bool bFirstResult = hash->hashFinal(digest);

	delete hash;
	hash = NULL;

	if (!bFirstResult)
	{
		return false;
	}
	
	gcry_sexp_t dsa = pk->getGCRYPTKey();

	// Perform the signature operation
	unsigned int sigLen = pk->getOutputLength();
	signature.resize(sigLen);
	memset(&signature[0], 0, sigLen);
	gcry_mpi_t digestMpi = GCRYPTUtil::byteString2mpi(digest);
	gcry_sexp_t digestSexpr = NULL;
	gcry_error_t rv = gcry_sexp_build(&digestSexpr, NULL, "(data (flags raw) (value %M))", digestMpi);
	gcry_mpi_release(digestMpi);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build data S-expr");

		return false;
	}
	gcry_sexp_t sigSexpr = NULL;
	rv = gcry_pk_sign(&sigSexpr, digestSexpr, dsa);
	gcry_sexp_release(digestSexpr);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to sign");

		return false;
	}
	if (sigSexpr == NULL)
		return false;
	// Store the 2 values with padding
	gcry_sexp_t rx = gcry_sexp_find_token(sigSexpr, "r", 0);
	gcry_sexp_t sx = gcry_sexp_find_token(sigSexpr, "s", 0);
	gcry_sexp_release(sigSexpr);
	if ((rx == NULL) || (sx == NULL))
	{
		ERROR_MSG("failed to parse signature");

		return false;
	}
	gcry_mpi_t ri = gcry_sexp_nth_mpi(rx, 1, GCRYMPI_FMT_USG);
	gcry_mpi_t si = gcry_sexp_nth_mpi(sx, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(rx);
	gcry_sexp_release(sx);
	if ((ri == NULL) || (si == NULL))
	{
		ERROR_MSG("failed to read signature");

		return false;
	}
	ByteString r = GCRYPTUtil::mpi2ByteString(ri);
	ByteString s = GCRYPTUtil::mpi2ByteString(si);
	gcry_mpi_release(ri);
	gcry_mpi_release(si);
	memcpy(&signature[sigLen / 2 - r.size()], r.const_byte_str(), r.size());
	memcpy(&signature[sigLen - s.size()], s.const_byte_str(), s.size());
	return true;
}

// Verification functions
bool GCRYPTDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("dsa"))
	{
		// Separate implementation for DSA verification without hash computation

		// Check if the private key is the right type
		if (!publicKey->isOfType(GCRYPTDSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// Perform the verify operation
		GCRYPTDSAPublicKey* pk = (GCRYPTDSAPublicKey*) publicKey;
		unsigned int sigLen = pk->getOutputLength();
		if (signature.size() != sigLen)
			return false;
		ByteString r;
		r.resize(sigLen / 2);
		memcpy(&r[0], signature.const_byte_str(), r.size());
		ByteString s;
		s.resize(sigLen / 2);
		memcpy(&s[0], signature.const_byte_str() + sigLen / 2, s.size());
		gcry_mpi_t ri = GCRYPTUtil::byteString2mpi(r);
		gcry_mpi_t si = GCRYPTUtil::byteString2mpi(s);
		gcry_sexp_t sigSexpr = NULL;
		gcry_error_t rv = gcry_sexp_build(&sigSexpr, NULL, "(sig-val (dsa (r %M) (s %M)))", ri, si);
		gcry_mpi_release(ri);
		gcry_mpi_release(si);
		if (rv != GPG_ERR_NO_ERROR)
		{
			ERROR_MSG("failed to build signature S-expr");

			return false;
		}
		gcry_mpi_t dataMpi = GCRYPTUtil::byteString2mpi(originalData);
		gcry_sexp_t dataSexpr = NULL;
		rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags raw) (value %M))", dataMpi);
		gcry_mpi_release(dataMpi);
		if (rv != GPG_ERR_NO_ERROR)
		{
			ERROR_MSG("failed to build data S-expr");

			gcry_sexp_release(sigSexpr);

			return false;
		}
		rv = gcry_pk_verify(sigSexpr, dataSexpr, pk->getGCRYPTKey());
		gcry_sexp_release(sigSexpr);
		gcry_sexp_release(dataSexpr);
		if (rv != GPG_ERR_NO_ERROR)
		{
			if (gcry_err_code(rv) != GPG_ERR_BAD_SIGNATURE)
				ERROR_MSG("DSA verify failed (0x%08X)", rv);

			return false;
		}
		return true;
	}
	else
	{
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism);
	}
}

bool GCRYPTDSA::verifyInit(PublicKey* publicKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(GCRYPTDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("dsa-sha1"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("dsa-sha224"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha224");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("dsa-sha256"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha256");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("dsa-sha384"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha384");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("dsa-sha512"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha512");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}

	if (hash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTDSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (!hash->hashUpdate(originalData))
	{
		delete hash;
		hash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTDSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	GCRYPTDSAPublicKey* pk = (GCRYPTDSAPublicKey*) currentPublicKey;

	std::string lowerMechanism;
	lowerMechanism.resize(currentMechanism.size());
	std::transform(currentMechanism.begin(), currentMechanism.end(), lowerMechanism.begin(), tolower);

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString digest;

	bool bFirstResult = hash->hashFinal(digest);

	delete hash;
	hash = NULL;

	if (!bFirstResult)
	{
		return false;
	}

	// Perform the verify operation
	unsigned int sigLen = pk->getOutputLength();
	if (signature.size() != sigLen)
		return false;
	ByteString r;
	r.resize(sigLen / 2);
	memcpy(&r[0], signature.const_byte_str(), r.size());
	ByteString s;
	s.resize(sigLen / 2);
	memcpy(&s[0], signature.const_byte_str() + sigLen / 2, s.size());
	gcry_mpi_t ri = GCRYPTUtil::byteString2mpi(r);
	gcry_mpi_t si = GCRYPTUtil::byteString2mpi(s);
	gcry_sexp_t sigSexpr = NULL;
	gcry_error_t rv = gcry_sexp_build(&sigSexpr, NULL, "(sig-val (dsa (r %M) (s %M)))", ri, si);
	gcry_mpi_release(ri);
	gcry_mpi_release(si);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build signature S-expr");

		return false;
	}
	gcry_mpi_t digestMpi = GCRYPTUtil::byteString2mpi(digest);
	gcry_sexp_t digestSexpr = NULL;
	rv = gcry_sexp_build(&digestSexpr, NULL, "(data (flags raw) (value %M))", digestMpi);
	gcry_mpi_release(digestMpi);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build digest S-expr");

		gcry_sexp_release(sigSexpr);

		return false;
	}
	rv = gcry_pk_verify(sigSexpr, digestSexpr, pk->getGCRYPTKey());
	gcry_sexp_release(sigSexpr);
	gcry_sexp_release(digestSexpr);
	if (rv != GPG_ERR_NO_ERROR)
	{
		if (gcry_err_code(rv) != GPG_ERR_BAD_SIGNATURE)
			ERROR_MSG("DSA verify failed (0x%08X)", rv);

		return false;
	}

	return true;
}

// Encryption functions
bool GCRYPTDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/, ByteString& /*encryptedData*/, const std::string /*padding*/)
{
	ERROR_MSG("DSA does not support encryption");

	return false;
}

// Decryption functions
bool GCRYPTDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/, ByteString& /*data*/, const std::string /*padding*/)
{
	ERROR_MSG("DSA does not support decryption");

	return false;
}

// Key factory
bool GCRYPTDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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
	gcry_mpi_t pi = GCRYPTUtil::byteString2mpi(params->getP());
	gcry_mpi_t qi = GCRYPTUtil::byteString2mpi(params->getQ());
	gcry_mpi_t gi = GCRYPTUtil::byteString2mpi(params->getG());
	gcry_sexp_t paramSexpr = NULL;
	gcry_error_t rv = gcry_sexp_build(&paramSexpr, NULL, "(genkey (dsa (domain (p %M) (q %M) (g %M))))", pi, qi, gi);
	gcry_mpi_release(pi);
	gcry_mpi_release(qi);
	gcry_mpi_release(gi);
	if ((rv != GPG_ERR_NO_ERROR) || (paramSexpr == NULL))
	{
		ERROR_MSG("Failed to build genkey S-expr");

		return false;
	}
	gcry_sexp_t dsa = NULL;
	rv = gcry_pk_genkey(&dsa, paramSexpr);
	gcry_sexp_release(paramSexpr);
	if ((rv != GPG_ERR_NO_ERROR) || (dsa == NULL))
	{
		ERROR_MSG("Failed to generate DSA key pair");

		return false;
	}
	gcry_sexp_t pubSexpr = gcry_sexp_find_token(dsa, "public-key", 0);
	gcry_sexp_t privSexpr = gcry_sexp_find_token(dsa, "private-key", 0);
	gcry_sexp_release(dsa);

	if ((pubSexpr == NULL) || (privSexpr == NULL))
	{
		ERROR_MSG("Failed to parse DSA key pair");

		return false;
	}

	// Create an asymmetric key-pair object to return
	GCRYPTDSAKeyPair* kp = new GCRYPTDSAKeyPair();

	((GCRYPTDSAPublicKey*) kp->getPublicKey())->setFromGCRYPT(pubSexpr);
	((GCRYPTDSAPrivateKey*) kp->getPrivateKey())->setFromGCRYPT(privSexpr);

	*ppKeyPair = kp;

	// Release the keys
	gcry_sexp_release(pubSexpr);
	gcry_sexp_release(privSexpr);

	return true;
}

// 512..1024 -> SHA1
unsigned long GCRYPTDSA::getMinKeySize()
{
	return 512;
}

// 2048 -> SHA224, 3072 -> SHA256, 7680 -> SHA384, 15360 -> SHA512
unsigned long GCRYPTDSA::getMaxKeySize()
{
	return 15360;
}

bool GCRYPTDSA::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* /*rng = NULL*/)
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

	gcry_sexp_t paramSexpr = NULL;
	gcry_error_t rv = gcry_sexp_build(&paramSexpr, NULL, "(genkey (dsa (nbits %u)))", bitLen);
	if ((rv != GPG_ERR_NO_ERROR) || (paramSexpr == NULL))
	{
		ERROR_MSG("Failed to build genkey S-expr");

		return false;
	}
	gcry_sexp_t dsa = NULL;
	rv = gcry_pk_genkey(&dsa, paramSexpr);
	gcry_sexp_release(paramSexpr);
	if ((rv != GPG_ERR_NO_ERROR) || (dsa == NULL))
	{
		ERROR_MSG("Failed to generate %d bit DSA parameters", bitLen);

		return false;
	}
	gcry_sexp_t keySexpr = gcry_sexp_find_token(dsa, "public-key", 0);
	gcry_sexp_release(dsa);
	if (keySexpr == NULL)
	{
		ERROR_MSG("Failed to parse DSA parameters");

		return false;
	}

	// Store the DSA parameters
	DSAParameters* params = new DSAParameters();

	gcry_sexp_t px = gcry_sexp_find_token(keySexpr, "p", 0);
	if (px == NULL)
	{
		gcry_sexp_release(keySexpr);

		return false;
	}
	gcry_mpi_t pi = gcry_sexp_nth_mpi(px, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(px);
	if (pi == NULL)
	{
		gcry_sexp_release(keySexpr);

		return false;
	}
	ByteString p = GCRYPTUtil::mpi2ByteString(pi);
	params->setP(p);
	gcry_mpi_release(pi);

	gcry_sexp_t qx = gcry_sexp_find_token(keySexpr, "q", 0);
	if (qx == NULL)
	{
		gcry_sexp_release(keySexpr);

		return false;
	}
	gcry_mpi_t qi = gcry_sexp_nth_mpi(qx, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(qx);
	if (qi == NULL)
	{
		gcry_sexp_release(keySexpr);

		return false;
	}
	ByteString q = GCRYPTUtil::mpi2ByteString(qi);
	params->setQ(q);
	gcry_mpi_release(qi);

	gcry_sexp_t gx = gcry_sexp_find_token(keySexpr, "g", 0);
	if (gx == NULL)
	{
		gcry_sexp_release(keySexpr);

		return false;
	}
	gcry_mpi_t gi = gcry_sexp_nth_mpi(gx, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(gx);
	if (gi == NULL)
	{
		gcry_sexp_release(keySexpr);

		return false;
	}
	ByteString g = GCRYPTUtil::mpi2ByteString(gi);
	params->setG(g);
	gcry_mpi_release(gi);

	*ppParams = params;

	gcry_sexp_release(keySexpr);

	return true;
}

bool GCRYPTDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	GCRYPTDSAKeyPair* kp = new GCRYPTDSAKeyPair();

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

bool GCRYPTDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	GCRYPTDSAPublicKey* pub = new GCRYPTDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool GCRYPTDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	GCRYPTDSAPrivateKey* priv = new GCRYPTDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* GCRYPTDSA::newPublicKey()
{
	return (PublicKey*) new GCRYPTDSAPublicKey();
}

PrivateKey* GCRYPTDSA::newPrivateKey()
{
	return (PrivateKey*) new GCRYPTDSAPrivateKey();
}
	
AsymmetricParameters* GCRYPTDSA::newParameters()
{
	return (AsymmetricParameters*) new DSAParameters();
}

bool GCRYPTDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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

