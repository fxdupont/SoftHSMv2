/*
 * Copyright (c) 2014 SURFnet bv
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
 PSSLRSA.cpp

 PolarSSL RSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "PSSLRSA.h"
#include "PSSLRNG.h"
#include "CryptoFactory.h"
#include "PSSLCryptoFactory.h"
#include "RSAParameters.h"
#include "PSSLRSAKeyPair.h"
#include <algorithm>
#include <polarssl/ctr_drbg.h>

// Constructor
PSSLRSA::PSSLRSA()
{
	pCurrentHash = NULL;
	pSecondHash = NULL;
	sLen = 0;
}

// Destructor
PSSLRSA::~PSSLRSA()
{
	if (pCurrentHash != NULL)
	{
		delete pCurrentHash;
	}

	if (pSecondHash != NULL)
	{
		delete pSecondHash;
	}
}

// Signing functions
bool PSSLRSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		   ByteString& signature, const AsymMech::Type mechanism,
		   const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::RSA_PKCS)
	{
		// Separate implementation for RSA PKCS #1 signing without hash computation

		// Check if the private key is the right type
		if (!privateKey->isOfType(PSSLRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// In case of PKCS #1 signing the length of the input data may not exceed 40% of the
		// modulus size
		PSSLRSAPrivateKey* psslKey = (PSSLRSAPrivateKey*) privateKey;

		size_t allowedLen = psslKey->getN().size() - 11;

		if (dataToSign.size() > allowedLen)
		{
			ERROR_MSG("Data to sign exceeds maximum for PKCS #1 signature");

			return false;
		}

		// Perform the signature operation
		signature.resize(psslKey->getN().size());

		rsa_context* rsa = psslKey->getPSSLKey();
		PSSLRNG* rng = (PSSLRNG*) PSSLCryptoFactory::i()->getRNG();

		if (rsa_rsaes_pkcs1_v15_encrypt(rsa, ctr_drbg_random, rng->getCTX(), RSA_PRIVATE, dataToSign.size(), dataToSign.const_byte_str(), &signature[0]) != 0)
		{
			ERROR_MSG("An error occurred while performing a PKCS #1 signature");

			return false;
		}

		return true;
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Separate implementation for raw RSA signing

		// Check if the private key is the right type
		if (!privateKey->isOfType(PSSLRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// In case of raw RSA, the length of the input data must match the length of the modulus
		PSSLRSAPrivateKey* psslKey = (PSSLRSAPrivateKey*) privateKey;

		if (dataToSign.size() != psslKey->getN().size())
		{
			ERROR_MSG("Size of data to sign does not match the modulus size");

			return false;
		}

		// Perform the signature operation
		signature.resize(psslKey->getN().size());

		rsa_context* rsa = psslKey->getPSSLKey();
		PSSLRNG* rng = (PSSLRNG*) PSSLCryptoFactory::i()->getRNG();

		if (rsa_private(rsa, ctr_drbg_random, rng->getCTX(), dataToSign.const_byte_str(), &signature[0]) != 0)
		{
			ERROR_MSG("An error occurred while performing a raw RSA signature");

			return false;
		}

		return true;
	}
	else
	{
		// Call default implementation
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, param, paramLen);
	}
}

bool PSSLRSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
		       const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(PSSLRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	HashAlgo::Type hash1 = HashAlgo::Unknown;
	HashAlgo::Type hash2 = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			hash1 = HashAlgo::MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA1 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-20))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-28))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-32))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-48))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((privateKey->getBitLength()+6)/8-2-64))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SSL:
			hash1 = HashAlgo::MD5;
			hash2 = HashAlgo::SHA1;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash1);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if (hash2 != HashAlgo::Unknown)
	{
		pSecondHash = CryptoFactory::i()->getHashAlgorithm(hash2);

		if (pSecondHash == NULL || !pSecondHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;

			if (pSecondHash != NULL)
			{
				delete pSecondHash;
				pSecondHash = NULL;
			}

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
		}
	}

	return true;
}

bool PSSLRSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if ((pSecondHash != NULL) && !pSecondHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		delete pSecondHash;
		pSecondHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLRSA::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	PSSLRSAPrivateKey* pk = (PSSLRSAPrivateKey*) currentPrivateKey;
	AsymMech::Type mechanism = currentMechanism;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString firstHash, secondHash;

	bool bFirstResult = pCurrentHash->hashFinal(firstHash);
	bool bSecondResult = (pSecondHash != NULL) ? pSecondHash->hashFinal(secondHash) : true;

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (pSecondHash != NULL)
	{
		delete pSecondHash;

		pSecondHash = NULL;
	}

	if (!bFirstResult || !bSecondResult)
	{
		return false;
	}

	ByteString digest = firstHash + secondHash;

	// Resize the data block for the signature to the modulus size of the key
	signature.resize(pk->getN().size());

	// Determine the signature MD type
	bool isPSS = false;
	md_type_t type = POLARSSL_MD_NONE;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			type = POLARSSL_MD_MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			type = POLARSSL_MD_SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			type = POLARSSL_MD_SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			type = POLARSSL_MD_SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			type = POLARSSL_MD_SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			type = POLARSSL_MD_SHA512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA512;
			break;
		case AsymMech::RSA_SSL:
			type = POLARSSL_MD_NONE;
			break;
		default:
			break;
	}

	// Perform the signature operation
	rsa_context* rsa = pk->getPSSLKey();
	PSSLRNG* rng = (PSSLRNG*) PSSLCryptoFactory::i()->getRNG();

	if (isPSS)
	{
		rsa_set_padding(rsa, RSA_PKCS_V21, type);
	}
	else
	{
		rsa_set_padding(rsa, RSA_PKCS_V15, type);
	}

	if (rsa_pkcs1_sign(rsa, ctr_drbg_random, rng->getCTX(), RSA_PRIVATE, type, digest.size(), digest.const_byte_str(), &signature[0]) != 0)
	{
		ERROR_MSG("RSA sign failed");

		return false;
	}

	return true;
}

// Verification functions
bool PSSLRSA::verify(PublicKey* publicKey, const ByteString& originalData,
		     const ByteString& signature, const AsymMech::Type mechanism,
		     const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism == AsymMech::RSA_PKCS)
	{
		// Specific implementation for PKCS #1 only verification; originalData is assumed to contain
		// a digestInfo structure and verification is performed by comparing originalData to the data
		// recovered from the signature

		// Check if the public key is the right type
		if (!publicKey->isOfType(PSSLRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// Perform the RSA public key operation
		PSSLRSAPublicKey* psslKey = (PSSLRSAPublicKey*) publicKey;

		ByteString recoveredData;

		recoveredData.resize(psslKey->getN().size());

		rsa_context* rsa = psslKey->getPSSLKey();
		PSSLRNG* rng = (PSSLRNG*) PSSLCryptoFactory::i()->getRNG();

		size_t retLen;
		if (rsa_rsaes_pkcs1_v15_decrypt(rsa, ctr_drbg_random, rng->getCTX(), RSA_PUBLIC, &retLen, signature.const_byte_str(), &recoveredData[0], recoveredData.size()) != 0)
		{
			ERROR_MSG("Public key operation failed");

			return false;
		}

		recoveredData.resize(retLen);

		return (originalData == recoveredData);
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Specific implementation for raw RSA verifiction; originalData is assumed to contain the
		// full input data used to compute the signature and verification is performed by comparing
		// originalData to the data recovered from the signature

		// Check if the public key is the right type
		if (!publicKey->isOfType(PSSLRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");

			return false;
		}

		// Perform the RSA public key operation
		PSSLRSAPublicKey* psslKey = (PSSLRSAPublicKey*) publicKey;

		ByteString recoveredData;

		recoveredData.resize(psslKey->getN().size());

		rsa_context* rsa = psslKey->getPSSLKey();

		if (rsa_public(rsa, signature.const_byte_str(), &recoveredData[0]) != 0)
		{
			ERROR_MSG("Public key operation failed");

			return false;
		}

		return (originalData == recoveredData);
	}
	else
	{
		// Call the generic function
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, param, paramLen);
	}
}

bool PSSLRSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			 const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(PSSLRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	HashAlgo::Type hash1 = HashAlgo::Unknown;
	HashAlgo::Type hash2 = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			hash1 = HashAlgo::MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA1 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-20))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA224 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-28))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA256 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-32))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA384 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-48))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			if (param == NULL || paramLen != sizeof(RSA_PKCS_PSS_PARAMS) ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->hashAlg != HashAlgo::SHA512 ||
			    ((RSA_PKCS_PSS_PARAMS*) param)->mgf != AsymRSAMGF::MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = ((RSA_PKCS_PSS_PARAMS*) param)->sLen;
			if (sLen > ((publicKey->getBitLength()+6)/8-2-64))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SSL:
			hash1 = HashAlgo::MD5;
			hash2 = HashAlgo::SHA1;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash1);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if (hash2 != HashAlgo::Unknown)
	{
		pSecondHash = CryptoFactory::i()->getHashAlgorithm(hash2);

		if (pSecondHash == NULL || !pSecondHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;

			if (pSecondHash != NULL)
			{
				delete pSecondHash;
				pSecondHash = NULL;
			}

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
		}
	}

	return true;
}

bool PSSLRSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if ((pSecondHash != NULL) && !pSecondHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		delete pSecondHash;
		pSecondHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLRSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	PSSLRSAPublicKey* pk = (PSSLRSAPublicKey*) currentPublicKey;
	AsymMech::Type mechanism = currentMechanism;

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString firstHash, secondHash;

	bool bFirstResult = pCurrentHash->hashFinal(firstHash);
	bool bSecondResult = (pSecondHash != NULL) ? pSecondHash->hashFinal(secondHash) : true;

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (pSecondHash != NULL)
	{
		delete pSecondHash;

		pSecondHash = NULL;
	}

	if (!bFirstResult || !bSecondResult)
	{
		return false;
	}

	ByteString digest = firstHash + secondHash;

	// Determine the signature MD type
	bool isPSS = false;
	md_type_t type = POLARSSL_MD_NONE;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			type = POLARSSL_MD_MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			type = POLARSSL_MD_SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			type = POLARSSL_MD_SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			type = POLARSSL_MD_SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			type = POLARSSL_MD_SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			type = POLARSSL_MD_SHA512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS_PSS:
			isPSS = true;
			type = POLARSSL_MD_SHA512;
			break;
		case AsymMech::RSA_SSL:
			type = POLARSSL_MD_NONE;
			break;
		default:
			break;
	}

	// Perform the verify operation
	rsa_context* rsa = pk->getPSSLKey();
	PSSLRNG* rng = (PSSLRNG*) PSSLCryptoFactory::i()->getRNG();

	if (isPSS)
	{
		rsa_set_padding(rsa, RSA_PKCS_V21, type);
	}
	else
	{
		rsa_set_padding(rsa, RSA_PKCS_V15, type);
	}

	ByteString plain;
	plain.resize(pk->getN().size());
	int ret = rsa_pkcs1_verify(rsa, ctr_drbg_random, rng->getCTX(), RSA_PUBLIC, type, digest.size(), digest.const_byte_str(), signature.const_byte_str());
	if (ret == 0)
	{
		return true;
	}
	else if (ret == POLARSSL_ERR_RSA_VERIFY_FAILED)
	{
		return false;
	}
	else
	{
		ERROR_MSG("RSA verify failed -(0x%08X)", -ret);

		return false;
	}
}

// Encryption functions
bool PSSLRSA::encrypt(PublicKey* publicKey, const ByteString& data,
		      ByteString& encryptedData, const AsymMech::Type padding)
{
	// Check if the public key is the right type
	if (!publicKey->isOfType(PSSLRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	// Retrieve the PolarSSL key object
	rsa_context* rsa = ((PSSLRSAPublicKey*) publicKey)->getPSSLKey();

	// Perform the RSA operation
	encryptedData.resize(mpi_size(&rsa->N));

	if (padding == AsymMech::RSA)
	{
		// The size of the input data should be exactly equal to the modulus length
		if (data.size() != mpi_size(&rsa->N))
		{
			ERROR_MSG("Incorrect amount of input data supplied for raw RSA encryption");

			return false;
		}

		if (rsa_public(rsa, data.const_byte_str(), &encryptedData[0]) != 0)
		{
			ERROR_MSG("RSA public key encryption failed");

			return false;
		}

		return true;
	}

	// Check the data and padding algorithm
	if (padding == AsymMech::RSA_PKCS)
	{
		// The size of the input data cannot be more than the modulus
		// length of the key - 11
		if (data.size() > (mpi_size(&rsa->N) - 11))
		{
			ERROR_MSG("Too much data supplied for RSA PKCS #1 encryption");

			return false;
		}

		rsa_set_padding(rsa, RSA_PKCS_V15, POLARSSL_MD_NONE);
	}
	else if (padding == AsymMech::RSA_PKCS_OAEP)
	{
		// The size of the input data cannot be more than the modulus
		// length of the key - 41
		if (data.size() > (mpi_size(&rsa->N) - 41))
		{
			ERROR_MSG("Too much data supplied for RSA OAEP encryption");

			return false;
		}

		rsa_set_padding(rsa, RSA_PKCS_V21, POLARSSL_MD_NONE);
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);

		return false;
	}

	PSSLRNG* rng = (PSSLRNG*) PSSLCryptoFactory::i()->getRNG();

	if (rsa_pkcs1_encrypt(rsa, ctr_drbg_random, rng->getCTX(), RSA_PUBLIC, data.size(), data.const_byte_str(), &encryptedData[0]) != 0)
	{
		ERROR_MSG("RSA public key encryption failed");

		return false;
	}

	return true;
}

// Decryption functions
bool PSSLRSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
		      ByteString& data, const AsymMech::Type padding)
{
	// Check if the private key is the right type
	if (!privateKey->isOfType(PSSLRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	// Retrieve the PolarSSL key object
	rsa_context* rsa = ((PSSLRSAPrivateKey*) privateKey)->getPSSLKey();

	// Check the input size
	if (encryptedData.size() != mpi_size(&rsa->N))
	{
		ERROR_MSG("Invalid amount of input data supplied for RSA decryption");

		return false;
	}

	// Perform the RSA operation
	data.resize(mpi_size(&rsa->N));

	PSSLRNG* rng = (PSSLRNG*) PSSLCryptoFactory::i()->getRNG();

	if (padding == AsymMech::RSA)
	{
		if (rsa_private(rsa, ctr_drbg_random, rng->getCTX(), encryptedData.const_byte_str(), &data[0]) != 0)
		{
			ERROR_MSG("RSA private key decryption failed");

			return false;
		}
	}

	if (padding == AsymMech::RSA_PKCS)
	{
		rsa_set_padding(rsa, RSA_PKCS_V15, POLARSSL_MD_NONE);
	}
	else if (padding == AsymMech::RSA_PKCS_OAEP)
	{
		rsa_set_padding(rsa, RSA_PKCS_V21, POLARSSL_MD_NONE);
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);

		return false;
	}

	size_t decSize;
	if (rsa_pkcs1_decrypt(rsa, ctr_drbg_random, rng->getCTX(), RSA_PRIVATE, &decSize, encryptedData.const_byte_str(), &data[0], data.size()) != 0)
	{
		ERROR_MSG("RSA private key decryption failed");

		return false;
	}

	data.resize(decSize);

	return true;
}

// Key factory
bool PSSLRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
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
		ERROR_MSG("This RSA key size (%lu) is not supported", params->getBitLength());

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
	rsa_context rsa;
	rsa_init(&rsa, RSA_PKCS_V15, POLARSSL_MD_NONE);
	PSSLRNG* rng = (PSSLRNG*) PSSLCryptoFactory::i()->getRNG();

	if (rsa_gen_key(&rsa, ctr_drbg_random, rng->getCTX(), params->getBitLength(), (int)e) != 0)
	{
		ERROR_MSG("RSA key generation failed");

		return false;
	}

	// Create an asymmetric key-pair object to return
	PSSLRSAKeyPair* kp = new PSSLRSAKeyPair();

	((PSSLRSAPublicKey*) kp->getPublicKey())->setFromPSSL(rsa);
	((PSSLRSAPrivateKey*) kp->getPrivateKey())->setFromPSSL(rsa);

	*ppKeyPair = kp;

	// Release the key
	rsa_free(&rsa);

	return true;
}

unsigned long PSSLRSA::getMinKeySize()
{
	return 128;
}

unsigned long PSSLRSA::getMaxKeySize()
{
	return POLARSSL_MPI_MAX_SIZE * 8;
}

bool PSSLRSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	PSSLRSAKeyPair* kp = new PSSLRSAKeyPair();

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

bool PSSLRSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	PSSLRSAPublicKey* pub = new PSSLRSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool PSSLRSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	PSSLRSAPrivateKey* priv = new PSSLRSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* PSSLRSA::newPublicKey()
{
	return (PublicKey*) new PSSLRSAPublicKey();
}

PrivateKey* PSSLRSA::newPrivateKey()
{
	return (PrivateKey*) new PSSLRSAPrivateKey();
}

AsymmetricParameters* PSSLRSA::newParameters()
{
	return (AsymmetricParameters*) new RSAParameters();
}

bool PSSLRSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	RSAParameters* params = new RSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
