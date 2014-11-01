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
 PSSLCryptoFactory.cpp

 This is an PolarSSL based cryptographic algorithm factory
 *****************************************************************************/

#include "config.h"
#include "MutexFactory.h"
#include "PSSLCryptoFactory.h"
#include "PSSLRNG.h"
#include "PSSLAES.h"
#include "PSSLDES.h"
#include "PSSLMD5.h"
#include "PSSLSHA1.h"
#include "PSSLSHA224.h"
#include "PSSLSHA256.h"
#include "PSSLSHA384.h"
#include "PSSLSHA512.h"
#include "PSSLHMAC.h"
#include "PSSLRSA.h"
//#include "PSSLDH.h"
#ifdef WITH_ECC
#include "PSSLECDH.h"
#include "PSSLECDSA.h"
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#include <algorithm>
#include <string.h>
//#include <polarssl/threading.h>
#include <polarssl/md.h>
#include <polarssl/cipher.h>
#include <polarssl/pk.h>

// Initialise the one-and-only instance
std::auto_ptr<PSSLCryptoFactory> PSSLCryptoFactory::instance(NULL);

// Constructor
PSSLCryptoFactory::PSSLCryptoFactory()
{
	// Initialise the one-and-only RNG
	rng = new PSSLRNG();
}

// Destructor
PSSLCryptoFactory::~PSSLCryptoFactory()
{
	// Destroy the one-and-only RNG
	delete rng;
}

// Return the one-and-only instance
PSSLCryptoFactory* PSSLCryptoFactory::i()
{
	if (!instance.get())
	{
		instance = std::auto_ptr<PSSLCryptoFactory>(new PSSLCryptoFactory());
	}

	return instance.get();
}

// This will destroy the one-and-only instance.
void PSSLCryptoFactory::reset()
{
	instance.reset();
}

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* PSSLCryptoFactory::getSymmetricAlgorithm(SymAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case SymAlgo::AES:
			return new PSSLAES();
		case SymAlgo::DES:
		case SymAlgo::DES3:
			return new PSSLDES();
		default:
			// No algorithm implementation is available
			ERROR_MSG("Unknown algorithm '%i'", algorithm);

			return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of an asymmetric algorithm
AsymmetricAlgorithm* PSSLCryptoFactory::getAsymmetricAlgorithm(AsymAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case AsymAlgo::RSA:
			return new PSSLRSA();
#ifdef notdef
		case AsymAlgo::DH:
			return new PSSLDH();
#endif
#ifdef WITH_ECC
		case AsymAlgo::ECDH:
			return new PSSLECDH();
		case AsymAlgo::ECDSA:
			return new PSSLECDSA();
#endif
		default:
			// No algorithm implementation is available
			ERROR_MSG("Unknown algorithm '%i'", algorithm);

			return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of a hash algorithm
HashAlgorithm* PSSLCryptoFactory::getHashAlgorithm(HashAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case HashAlgo::MD5:
			return new PSSLMD5();
		case HashAlgo::SHA1:
			return new PSSLSHA1();
		case HashAlgo::SHA224:
			return new PSSLSHA224();
		case HashAlgo::SHA256:
			return new PSSLSHA256();
		case HashAlgo::SHA384:
			return new PSSLSHA384();
		case HashAlgo::SHA512:
			return new PSSLSHA512();
		default:
			// No algorithm implementation is available
			ERROR_MSG("Unknown algorithm '%i'", algorithm);

			return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of a MAC algorithm
MacAlgorithm* PSSLCryptoFactory::getMacAlgorithm(MacAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case MacAlgo::HMAC_MD5:
			return new PSSLHMACMD5();
		case MacAlgo::HMAC_SHA1:
			return new PSSLHMACSHA1();
		case MacAlgo::HMAC_SHA224:
			return new PSSLHMACSHA224();
		case MacAlgo::HMAC_SHA256:
			return new PSSLHMACSHA256();
		case MacAlgo::HMAC_SHA384:
			return new PSSLHMACSHA384();
		case MacAlgo::HMAC_SHA512:
			return new PSSLHMACSHA512();
		default:
			// No algorithm implementation is available
			ERROR_MSG("Unknown algorithm '%i'", algorithm);

			return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Get the global RNG (may be an unique RNG per thread)
RNG* PSSLCryptoFactory::getRNG(RNGImpl::Type name /* = RNGImpl::Default */)
{
	if (name == RNGImpl::Default)
	{
		return rng;
	}
	else
	{
		// No RNG implementation is available
		ERROR_MSG("Unknown RNG '%i'", name);

		return NULL;
	}
}

