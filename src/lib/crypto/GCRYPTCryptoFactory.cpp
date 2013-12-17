/*
 * Copyright (c) 2010 SURFnet bv
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
 GCRYPTCryptoFactory.cpp

 This is a libgcrypt based cryptographic algorithm factory
 *****************************************************************************/

#include "config.h"
#include "GCRYPTCryptoFactory.h"
#include "GCRYPTAES.h"
#include "GCRYPTDES.h"
#include "GCRYPTMD5.h"
#include "GCRYPTSHA1.h"
#include "GCRYPTSHA224.h"
#include "GCRYPTSHA256.h"
#include "GCRYPTSHA384.h"
#include "GCRYPTSHA512.h"
#include "GCRYPTHMAC.h"
#include "GCRYPTDSA.h"
#include "GCRYPTRSA.h"
#if 0 // TODO
#include "GCRYPTDH.h"
#endif
#ifdef WITH_ECC
#include "GCRYPTECDH.h"
#include "GCRYPTECDSA.h"
#endif
#include "GCRYPTRNG.h"
#include <errno.h>

// Initialise the one-and-only instance
std::auto_ptr<GCRYPTCryptoFactory> GCRYPTCryptoFactory::instance(NULL);

static int mutex_init_callback(void **priv)
{
	Mutex* mtx = MutexFactory::i()->getMutex();

	if (mtx == NULL)
	{
		return ENOMEM;
	}
	*priv = mtx;
	return 0;
}

static int mutex_destroy_callback(void **priv)
{
	MutexFactory::i()->recycleMutex((Mutex *)*priv);
	*priv = NULL;
	return 0;
}

static int mutex_lock_callback(void **priv)
{
	((Mutex*)(*priv))->lock();
	return 0;
}

static int mutex_unlock_callback(void **priv)
{
	((Mutex*)(*priv))->unlock();
	return 0;
}

static struct gcry_thread_cbs gcry_thread_callbacks =
{
	GCRY_THREAD_OPTION_USER | (GCRY_THREAD_OPTION_VERSION << 8),
	NULL, // init
	mutex_init_callback,
	mutex_destroy_callback,
	mutex_lock_callback,
	mutex_unlock_callback,
	NULL, // read
	NULL, // write
	NULL, // select
	NULL, // waitpid
	NULL, // accept
	NULL, // connect
	NULL, // sendmsg
	NULL  // recvmsg
};

// Constructor
GCRYPTCryptoFactory::GCRYPTCryptoFactory()
{
	// Multi-thread support
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_thread_callbacks, 0);

	// Initialize libgcrypt
	gcry_check_version(GCRYPT_VERSION);

	// Random pool in secure memory
	gcry_control(GCRYCTL_USE_SECURE_RNDPOOL, 0);

	// Initialize secure memory to its default
	gcry_control(GCRYCTL_INIT_SECMEM, 1, 0);

	// Initialization is finished
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	// Initialise the one-and-only RNG
	rng = new GCRYPTRNG();

}

// Destructor
GCRYPTCryptoFactory::~GCRYPTCryptoFactory()
{
	// Destroy the one-and-only RNG
	delete rng;

	// Terminate the secure memory
	gcry_control(GCRYCTL_TERM_SECMEM, 0);
}

// Return the one-and-only instance
GCRYPTCryptoFactory* GCRYPTCryptoFactory::i()
{
	if (!instance.get())
	{
		instance = std::auto_ptr<GCRYPTCryptoFactory>(new GCRYPTCryptoFactory());
	}

	return instance.get();
}

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* GCRYPTCryptoFactory::getSymmetricAlgorithm(std::string algorithm)
{
        std::string lcAlgo;
        lcAlgo.resize(algorithm.size());
        std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

        if (!lcAlgo.compare("aes"))
        {
                return new GCRYPTAES();
        }
        else if (!lcAlgo.compare("des") || !lcAlgo.compare("3des"))
        {
                return new GCRYPTDES();
        }
        else
        {
                // No algorithm implementation is available
                ERROR_MSG("Unknown algorithm '%s'", lcAlgo.c_str());

                return NULL;
        }

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of an asymmetric algorithm
AsymmetricAlgorithm* GCRYPTCryptoFactory::getAsymmetricAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("rsa"))
	{
		return new GCRYPTRSA();
	}
	else if (!lcAlgo.compare("dsa"))
	{
		return new GCRYPTDSA();
	}
#if 0
	else if (!lcAlgo.compare("dh"))
	{
		return new GCRYPTDH();
	}
#endif
#ifdef WITH_ECC
	else if (!lcAlgo.compare("ecdh"))
	{
		return new GCRYPTECDH();
	}
	else if (!lcAlgo.compare("ecdsa"))
	{
		return new GCRYPTECDSA();
	}
#endif
	else
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", algorithm.c_str());

		return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of a hash algorithm
HashAlgorithm* GCRYPTCryptoFactory::getHashAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("md5"))
	{
		return new GCRYPTMD5();
	}
	else if (!lcAlgo.compare("sha1"))
	{
		return new GCRYPTSHA1();
	}
	else if (!lcAlgo.compare("sha224"))
	{
		return new GCRYPTSHA224();
	}
	else if (!lcAlgo.compare("sha256"))
	{
		return new GCRYPTSHA256();
	}
	else if (!lcAlgo.compare("sha384"))
	{
		return new GCRYPTSHA384();
	}
	else if (!lcAlgo.compare("sha512"))
	{
		return new GCRYPTSHA512();
	}
	else
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", algorithm.c_str());

		return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Create a concrete instance of a MAC algorithm
MacAlgorithm* GCRYPTCryptoFactory::getMacAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("hmac-md5"))
	{
		return new GCRYPTHMACMD5();
	}
	else if (!lcAlgo.compare("hmac-sha1"))
	{
		return new GCRYPTHMACSHA1();
	}
	else if (!lcAlgo.compare("hmac-sha224"))
	{
		return new GCRYPTHMACSHA224();
	}
	else if (!lcAlgo.compare("hmac-sha256"))
	{
		return new GCRYPTHMACSHA256();
	}
	else if (!lcAlgo.compare("hmac-sha384"))
	{
		return new GCRYPTHMACSHA384();
	}
	else if (!lcAlgo.compare("hmac-sha512"))
	{
		return new GCRYPTHMACSHA512();
	}
	else
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", algorithm.c_str());

		return NULL;
	}

	// No algorithm implementation is available
	return NULL;
}

// Get the global RNG (may be an unique RNG per thread)
RNG* GCRYPTCryptoFactory::getRNG(std::string name /* = "default" */)
{
	std::string lcAlgo;
	lcAlgo.resize(name.size());
	std::transform(name.begin(), name.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("default"))
	{
		return rng;
	}
	else
	{
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", name.c_str());

		return NULL;
	}
}
