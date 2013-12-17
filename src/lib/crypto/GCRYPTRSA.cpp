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
 GCRYPTRSA.cpp

 libgcrypt RSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "GCRYPTRSA.h"
#include "GCRYPTRNG.h"
#include "GCRYPTCryptoFactory.h"
#include "RSAParameters.h"
#include "GCRYPTRSAKeyPair.h"
#include "GCRYPTUtil.h"
#include <algorithm>

// Constructor
GCRYPTRSA::GCRYPTRSA()
{
	hash = NULL;
	hash2 = NULL;
}

// Destructor
GCRYPTRSA::~GCRYPTRSA()
{
	if (hash != NULL)
	{
		delete hash;
	}
	
	if (hash2 != NULL)
	{
		delete hash2;
	}
}

// Signing functions
bool GCRYPTRSA::sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const std::string mechanism)
{

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (lowerMechanism.compare("rsa-pkcs") && lowerMechanism.compare("rsa-raw"))
	{
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism);
	}

	// Separate implementation for RSA PKCS #1 and raw signing without hash computation

	// Check if the private key is the right type
	if (!privateKey->isOfType(GCRYPTRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
	
		return false;
	}

	GCRYPTRSAPrivateKey* GCRYPTKey = (GCRYPTRSAPrivateKey*) privateKey;
	gcry_sexp_t rsa = GCRYPTKey->getGCRYPTKey();

	if (!lowerMechanism.compare("rsa-pkcs"))
	{
		// BTW this is not supported by libcrypt (GPG_ERR_CONFLICT)
		ERROR_MSG("unsupported yet RSA sign mode 'raw pkcs'");

		return false;
	}

	if (!lowerMechanism.compare("rsa-pkcs"))
	{
		// In case of PKCS #1 signing the length of the input data
		// may not exceed 40% of the modulus size
		if (dataToSign.size() > GCRYPTKey->getN().size() - 11)
		{
			ERROR_MSG("Data to sign exceeds maximum for PKCS #1 signature");

			return false;
		}
	}
	else
	{
		// In case of raw RSA, the length of the input data
		// must match the length of the modulus
		if (dataToSign.size() != GCRYPTKey->getN().size())
		{
			ERROR_MSG("Size of data to sign does not match the modulus size");

			return false;
		}
	}

	// Perform the signature operation
	gcry_sexp_t dataSexpr = NULL;
	gcry_error_t rv;
	if (!lowerMechanism.compare("rsa-pkcs"))
	{
		gcry_mpi_t dataMpi = GCRYPTUtil::byteString2mpi(dataToSign);
		rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags pkcs1) (value %M))", dataMpi);
		gcry_mpi_release(dataMpi);
	}
	else
	{
		rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags raw) (value %b))", (int) dataToSign.size(), dataToSign.const_byte_str());
	}
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build data S-expr");

		return false;
	}

	gcry_sexp_t sigSexpr = NULL;
	rv = gcry_pk_sign(&sigSexpr, dataSexpr, rsa);
	gcry_sexp_release(dataSexpr);
	if ((rv != GPG_ERR_NO_ERROR) || (sigSexpr == NULL))
	{
		ERROR_MSG("failed to sign");

		return false;
	}

	// Store value
	gcry_sexp_t sx = gcry_sexp_find_token(sigSexpr, "s", 0);
	gcry_sexp_release(sigSexpr);
	if (sx == NULL)
	{
		ERROR_MSG("failed to parse signature");

		return false;
	}
	gcry_mpi_t si = gcry_sexp_nth_mpi(sx, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(sx);
	if (si == NULL)
	{
		ERROR_MSG("failed to read signature");

		return false;
	}
	signature = GCRYPTUtil::mpi2ByteString(si);
	gcry_mpi_release(si);

	return true;
}
	
bool GCRYPTRSA::signInit(PrivateKey* privateKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(GCRYPTRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("rsa-md5-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("md5");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha1-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha224-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha224");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha256-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha256");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha384-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha384");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha512-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha512");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
#ifndef notyet
	else if (!lowerMechanism.compare("rsa-ssl"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("md5");
		hash2 = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}

		if (!hash2->hashInit())
		{
			delete hash;
			hash = NULL;
			
			delete hash2;
			hash2 = NULL;
		}
	}
#endif

	if (hash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTRSA::signUpdate(const ByteString& dataToSign)
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

	if ((hash2 != NULL) && !hash2->hashUpdate(dataToSign))
	{
		delete hash;
		hash = NULL;

		delete hash2;
		hash2 = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTRSA::signFinal(ByteString& signature)
{	
	// Save necessary state before calling super class signFinal
	GCRYPTRSAPrivateKey* pk = (GCRYPTRSAPrivateKey*) currentPrivateKey;

	std::string lowerMechanism;
	lowerMechanism.resize(currentMechanism.size());
	std::transform(currentMechanism.begin(), currentMechanism.end(), lowerMechanism.begin(), tolower);

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString digest, digest2;

	bool result = hash->hashFinal(digest);
	bool result2 = (hash2 != NULL) ? hash2->hashFinal(digest2) : true;

	delete hash;
	hash = NULL;

	if (hash2 != NULL)
	{
		delete hash2;

		hash2 = NULL;
	}

	if (!result || !result2)
	{
		return false;
	}
	
	digest = digest + digest2;

	// Determine the signature hash type
	std::string type = "";

	if (!lowerMechanism.compare("rsa-md5-pkcs"))
	{
		type = "md5";
	}
	else if (!lowerMechanism.compare("rsa-sha1-pkcs"))
	{
		type = "sha1";
	}
	else if (!lowerMechanism.compare("rsa-sha224-pkcs"))
	{
		type = "sha224";
	}
	else if (!lowerMechanism.compare("rsa-sha256-pkcs"))
	{
		type = "sha256";
	}
	else if (!lowerMechanism.compare("rsa-sha384-pkcs"))
	{
		type = "sha384";
	}
	else if (!lowerMechanism.compare("rsa-sha512-pkcs"))
	{
		type = "sha512";
	}
	// TODO rsa-ssl

	// Perform the signature operation
	gcry_sexp_t rsa = pk->getGCRYPTKey();
	gcry_sexp_t dataSexpr = NULL;
	gcry_error_t rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags pkcs1) (hash %s %b))", type.c_str(), (int) digest.size(), (char*) digest.const_byte_str());

	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build data S-expr");

		return false;
	}
	gcry_sexp_t sigSexpr = NULL;
	rv = gcry_pk_sign(&sigSexpr, dataSexpr, rsa);
	gcry_sexp_release(dataSexpr);
	if ((rv != GPG_ERR_NO_ERROR) || (sigSexpr == NULL))
	{
		ERROR_MSG("failed to sign");

		return false;
	}

	// Store value
	gcry_sexp_t sx = gcry_sexp_find_token(sigSexpr, "s", 0);
	gcry_sexp_release(sigSexpr);
	if (sx == NULL)
	{
		ERROR_MSG("failed to parse signature");

		return false;
	}
	gcry_mpi_t si = gcry_sexp_nth_mpi(sx, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(sx);
	if (si == NULL)
	{
		ERROR_MSG("failed to read signature");

		return false;
	}
	signature = GCRYPTUtil::mpi2ByteString(si);
	gcry_mpi_release(si);

	return true;
}

// Verification functions
bool GCRYPTRSA::verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const std::string mechanism)
{
	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (lowerMechanism.compare("rsa-pkcs") && lowerMechanism.compare("rsa-raw"))
	{
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism);
	}


	if (!lowerMechanism.compare("rsa-pkcs"))
	{
		// BTW this is not supported by libcrypt (GPG_ERR_CONFLICT)
		ERROR_MSG("unsupported yet RSA verify mode 'raw pkcs'");

		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(GCRYPTRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
	
		return false;
	}

	// Perform the RSA public key operation
	GCRYPTRSAPublicKey* GCRYPTKey = (GCRYPTRSAPublicKey*) publicKey;
	gcry_sexp_t rsa = GCRYPTKey->getGCRYPTKey();
	gcry_mpi_t si = GCRYPTUtil::byteString2mpi(signature);
	gcry_sexp_t sigSexpr = NULL;
	gcry_error_t rv = gcry_sexp_build(&sigSexpr, NULL, "(sig-val (rsa (s %M)))", si);
	gcry_mpi_release(si);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build signature S-expr");

		return false;
	}

	gcry_sexp_t dataSexpr = NULL;
	if (!lowerMechanism.compare("rsa-pkcs"))
	{
		gcry_mpi_t dataMpi = GCRYPTUtil::byteString2mpi(originalData);
		rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags pkcs1) (value %M))", dataMpi);
		gcry_mpi_release(dataMpi);
	}
	else
	{
		rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags raw) (value %b))", (int) originalData.size(), originalData.const_byte_str());
	}
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build data S-expr");

		gcry_sexp_release(sigSexpr);

		return false;
	}

	rv = gcry_pk_verify(sigSexpr, dataSexpr, rsa);
	gcry_sexp_release(sigSexpr);
	gcry_sexp_release(dataSexpr);
	if (rv != GPG_ERR_NO_ERROR)
	{
		if (gcry_err_code(rv) != GPG_ERR_BAD_SIGNATURE)
			ERROR_MSG("RSA verify failed (0x%08X)", rv);

		return false;
	}

	return true;
}

bool GCRYPTRSA::verifyInit(PublicKey* publicKey, const std::string mechanism)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(GCRYPTRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	std::string lowerMechanism;
	lowerMechanism.resize(mechanism.size());
	std::transform(mechanism.begin(), mechanism.end(), lowerMechanism.begin(), tolower);

	if (!lowerMechanism.compare("rsa-md5-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("md5");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha1-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha224-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha224");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha256-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha256");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha384-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha384");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
	else if (!lowerMechanism.compare("rsa-sha512-pkcs"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("sha512");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}
	}
#ifdef notyet
	else if (!lowerMechanism.compare("rsa-ssl"))
	{
		hash = CryptoFactory::i()->getHashAlgorithm("md5");
		hash2 = CryptoFactory::i()->getHashAlgorithm("sha1");

		if (!hash->hashInit())
		{
			delete hash;
			hash = NULL;
		}

		if (!hash2->hashInit())
		{
			delete hash;
			hash = NULL;
			
			delete hash2;
			hash2 = NULL;
		}
	}
#endif

	if (hash == NULL)
	{
		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTRSA::verifyUpdate(const ByteString& originalData)
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

	if ((hash2 != NULL) && !hash2->hashUpdate(originalData))
	{
		delete hash;
		hash = NULL;

		delete hash2;
		hash2 = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTRSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	GCRYPTRSAPublicKey* pk = (GCRYPTRSAPublicKey*) currentPublicKey;
	gcry_sexp_t rsa = pk->getGCRYPTKey();

	std::string lowerMechanism;
	lowerMechanism.resize(currentMechanism.size());
	std::transform(currentMechanism.begin(), currentMechanism.end(), lowerMechanism.begin(), tolower);

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString digest, digest2;

	bool result = hash->hashFinal(digest);
	bool result2 = (hash2 != NULL) ? hash2->hashFinal(digest2) : true;

	delete hash;
	hash = NULL;

	if (hash2 != NULL)
	{
		delete hash2;

		hash2 = NULL;
	}

	if (!result || !result2)
	{
		return false;
	}
	
	digest = digest + digest2;

	// Determine the signature NID type
	std::string type = "";

	if (!lowerMechanism.compare("rsa-md5-pkcs"))
	{
		type = "md5";
	}
	else if (!lowerMechanism.compare("rsa-sha1-pkcs"))
	{
		type = "sha1";
	}
	else if (!lowerMechanism.compare("rsa-sha224-pkcs"))
	{
		type = "sha224";
	}
	else if (!lowerMechanism.compare("rsa-sha256-pkcs"))
	{
		type = "sha256";
	}
	else if (!lowerMechanism.compare("rsa-sha384-pkcs"))
	{
		type = "sha384";
	}
	else if (!lowerMechanism.compare("rsa-sha512-pkcs"))
	{
		type = "sha512";
	}
	// TODO rsa-ssl

	// Perform the verify operation
	gcry_mpi_t si = GCRYPTUtil::byteString2mpi(signature);
	gcry_sexp_t sigSexpr = NULL;
	gcry_error_t rv = gcry_sexp_build(&sigSexpr, NULL, "(sig-val (rsa (s %M)))", si);
	gcry_mpi_release(si);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build signature S-expr");

		return false;
	}

	gcry_sexp_t dataSexpr = NULL;
	gcry_mpi_t dataMpi = GCRYPTUtil::byteString2mpi(digest);
	rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags pkcs1) (hash %s %M))", type.c_str(), dataMpi);
	gcry_mpi_release(dataMpi);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build data S-expr");

		gcry_sexp_release(sigSexpr);

		return false;
	}

	rv = gcry_pk_verify(sigSexpr, dataSexpr, rsa);
	gcry_sexp_release(sigSexpr);
	gcry_sexp_release(dataSexpr);
	if (rv != GPG_ERR_NO_ERROR)
	{
		if (gcry_err_code(rv) != GPG_ERR_BAD_SIGNATURE)
			ERROR_MSG("RSA verify failed (0x%08X)", rv);

		return false;
	}

	return true;
}

// Encryption functions
bool GCRYPTRSA::encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const std::string padding)
{
	// Check if the public key is the right type
	if (!publicKey->isOfType(GCRYPTRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	std::string lowerPadding;
	lowerPadding.resize(padding.size());
	std::transform(padding.begin(), padding.end(), lowerPadding.begin(), tolower);

	// Retrieve the libgcrypt key object
	GCRYPTRSAPublicKey* GCRYPTKey = (GCRYPTRSAPublicKey*) publicKey;
	gcry_sexp_t rsa = GCRYPTKey->getGCRYPTKey();

	// Check the data and padding algorithm
	gcry_sexp_t dataSexpr = NULL;
	gcry_error_t rv;
	if (!lowerPadding.compare("rsa-pkcs"))
	{
		// The size of the input data cannot be more than the modulus
		// length of the key - 11
		if (data.size() > GCRYPTKey->getN().size() - 11)
		{
			ERROR_MSG("Too much data supplied for RSA PKCS #1 encryption");

			return false;
		}

		gcry_mpi_t dataMpi = GCRYPTUtil::byteString2mpi(data);
		rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags pkcs1) (value %M))", dataMpi);
		gcry_mpi_release(dataMpi);
	}
	else if (!lowerPadding.compare("rsa-pkcs-oaep"))
	{
		// The size of the input data cannot be more than the modulus
		// length of the key - 41
		if (data.size() > GCRYPTKey->getN().size() - 41)
		{
			ERROR_MSG("Too much data supplied for RSA OAEP encryption");

			return false;
		}

		rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags oaep) (hash-algo sha1) (value %b))", (int) data.size(), (char*) data.const_byte_str());
	}
	else if (!lowerPadding.compare("rsa-raw"))
	{
		// The size of the input data should be exactly equal to the modulus length
		if (data.size() != GCRYPTKey->getN().size())
		{
			ERROR_MSG("Incorrect amount of input data supplied for raw RSA encryption");

			return false;
		}

		rv = gcry_sexp_build(&dataSexpr, NULL, "(data (flags raw) (value %b))", (int) data.size(), (char*) data.const_byte_str());
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%s)", padding.c_str());

		return false;
	}
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("failed to build data S-expr");

		return false;
	}

	// Perform the RSA operation
	encryptedData.resize(GCRYPTKey->getN().size());
	memset(&encryptedData[0], 0, encryptedData.size());
	gcry_sexp_t encryptedSexpr = NULL;
	rv = gcry_pk_encrypt(&encryptedSexpr, dataSexpr, rsa);
	gcry_sexp_release(dataSexpr);
	if ((rv != GPG_ERR_NO_ERROR) || (encryptedSexpr == NULL))
	{
		ERROR_MSG("failed to encrypt");

		return false;
	}

	// Store value
	gcry_sexp_t ax = gcry_sexp_find_token(encryptedSexpr, "a", 0);
	gcry_sexp_release(encryptedSexpr);
	if (ax == NULL)
	{
		ERROR_MSG("failed to parse encrypted data");

		return false;
	}
	gcry_mpi_t ai = gcry_sexp_nth_mpi(ax, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(ax);
	if (ai == NULL)
	{
		ERROR_MSG("failed to read encrypted data");

		return false;
	}
	ByteString a = GCRYPTUtil::mpi2ByteString(ai);
	gcry_mpi_release(ai);
	if (a.size() > encryptedData.size())
	{
		ERROR_MSG("encrypted data overflow");

		return false;
	}
	memcpy(&encryptedData[encryptedData.size() - a.size()], a.const_byte_str(), a.size());

	return true;
}

// Decryption functions
bool GCRYPTRSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const std::string padding)
{
	// Check if the private key is the right type
	if (!privateKey->isOfType(GCRYPTRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	// Retrieve the libgcrypt key object
	GCRYPTRSAPrivateKey* GCRYPTKey = (GCRYPTRSAPrivateKey*) privateKey;
	gcry_sexp_t rsa = GCRYPTKey->getGCRYPTKey();

	// Check the input size
	if (encryptedData.size() != GCRYPTKey->getN().size())
	{
		ERROR_MSG("Invalid amount of input data supplied for RSA decryption");

		return false;
	}

	std::string lowerPadding;
	lowerPadding.resize(padding.size());
	std::transform(padding.begin(), padding.end(), lowerPadding.begin(), tolower);

	// Determine the libgcrypt padding algorithm
	gcry_sexp_t encryptedSexpr = NULL;
	gcry_mpi_t encryptedMpi = GCRYPTUtil::byteString2mpi(encryptedData);
	gcry_error_t rv;
	if (!lowerPadding.compare("rsa-pkcs"))
	{
		gcry_mpi_t encryptedMpi = GCRYPTUtil::byteString2mpi(encryptedData);
		rv = gcry_sexp_build(&encryptedSexpr, NULL, "(enc-val (flags pkcs1) (rsa (a %M)))", encryptedMpi);
	}
	else if (!lowerPadding.compare("rsa-pkcs-oaep"))
	{
		rv = gcry_sexp_build(&encryptedSexpr, NULL, "(enc-val (flags oaep) (hash-algo sha1) (rsa (a %M)))", encryptedMpi);
	}
	else if (!lowerPadding.compare("rsa-raw"))
	{
		rv = gcry_sexp_build(&encryptedSexpr, NULL, "(enc-val (flags) (rsa (a %M)))", encryptedMpi);
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%s)", padding.c_str());

		gcry_mpi_release(encryptedMpi);

		return false;
	}
	gcry_mpi_release(encryptedMpi);

	// Perform the RSA operation
	gcry_sexp_t dataSexpr = NULL;
	rv = gcry_pk_decrypt(&dataSexpr, encryptedSexpr, rsa);
	gcry_sexp_release(encryptedSexpr);
	if ((rv != GPG_ERR_NO_ERROR) || (dataSexpr == NULL))
	{
		ERROR_MSG("RSA private key decryption failed");

		return false;
	}

	// Store value
	gcry_sexp_t vx = gcry_sexp_find_token(dataSexpr, "value", 0);
	gcry_sexp_release(dataSexpr);
	if (vx == NULL)
	{
		ERROR_MSG("failed to parse decrypted data");

		return false;
	}
	gcry_mpi_t vi = gcry_sexp_nth_mpi(vx, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(vx);
	if (vi == NULL)
	{
		ERROR_MSG("failed to read decrypted data");

		return false;
	}

	if (lowerPadding.compare("rsa-raw"))
	{
		data = GCRYPTUtil::mpi2ByteString(vi);
		gcry_mpi_release(vi);
	}
	else
	{
		// No padding
		ByteString value = GCRYPTUtil::mpi2ByteString(vi);
		gcry_mpi_release(vi);
		data.resize(GCRYPTKey->getN().size());
		memset(&data[0], 0, data.size());
		if (value.size() > data.size())
		{
			ERROR_MSG("RSA raw decrypt overflow");

			return false;
		}
		memcpy(&data[data.size() - value.size()], value.const_byte_str(), value.size());
	}
	
	return true;
}

// Key factory
bool GCRYPTRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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
	gcry_sexp_t paramSexpr = NULL;
	gcry_error_t rv = gcry_sexp_build(&paramSexpr, NULL, "(genkey (rsa (nbits %u) (rsa-use-e %u)))", params->getBitLength(), e);
	if ((rv != GPG_ERR_NO_ERROR) || (paramSexpr == NULL))
	{
		ERROR_MSG("Failed to build genkey S-expr");

		return false;
	}
	gcry_sexp_t rsa = NULL;
	rv = gcry_pk_genkey(&rsa, paramSexpr);
	gcry_sexp_release(paramSexpr);
	if ((rv != GPG_ERR_NO_ERROR) || (rsa == NULL))
	{
		ERROR_MSG("Failed to generate RSA key pair");

		return false;
	}
	gcry_sexp_t pubSexpr = gcry_sexp_find_token(rsa, "public-key", 0);
	gcry_sexp_t privSexpr = gcry_sexp_find_token(rsa, "private-key", 0);
	gcry_sexp_release(rsa);
	if ((pubSexpr == NULL) || (privSexpr == NULL))
	{
		ERROR_MSG("Failed to parse RSA key pair");

		gcry_sexp_release(pubSexpr);
		gcry_sexp_release(privSexpr);

		return false;
	}

	// Create an asymmetric key-pair object to return
	GCRYPTRSAKeyPair* kp = new GCRYPTRSAKeyPair();

	((GCRYPTRSAPublicKey*) kp->getPublicKey())->setFromGCRYPT(pubSexpr);
	((GCRYPTRSAPrivateKey*) kp->getPrivateKey())->setFromGCRYPT(privSexpr);

	*ppKeyPair = kp;

	// Release the keys
	gcry_sexp_release(pubSexpr);
	gcry_sexp_release(privSexpr);

	return true;
}

unsigned long GCRYPTRSA::getMinKeySize() 
{ 
	return 512;
}

unsigned long GCRYPTRSA::getMaxKeySize() 
{ 
	return 10000;;
}

bool GCRYPTRSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	GCRYPTRSAKeyPair* kp = new GCRYPTRSAKeyPair();

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

bool GCRYPTRSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	GCRYPTRSAPublicKey* pub = new GCRYPTRSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool GCRYPTRSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	GCRYPTRSAPrivateKey* priv = new GCRYPTRSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* GCRYPTRSA::newPublicKey()
{
	return (PublicKey*) new GCRYPTRSAPublicKey();
}

PrivateKey* GCRYPTRSA::newPrivateKey()
{
	return (PrivateKey*) new GCRYPTRSAPrivateKey();
}
	
AsymmetricParameters* GCRYPTRSA::newParameters()
{
	return (AsymmetricParameters*) new RSAParameters();
}

