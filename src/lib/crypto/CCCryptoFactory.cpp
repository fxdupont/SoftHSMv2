/*
 * Copyright (c) 2013 SURFnet bv
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
 CCCryptoFactory.cpp

 This is an CommonCrypto based cryptographic algorithm factory
 *****************************************************************************/

#include "config.h"
#include "MutexFactory.h"
#include "CCCryptoFactory.h"
#include "CCMD5.h"
#include "CCSHA1.h"
#include "CCSHA224.h"
#include "CCSHA256.h"
#include "CCSHA384.h"
#include "CCSHA512.h"
#include "CCHMAC.h"
#include "CCRNG.h"
#ifdef notyet //////////
#include "CCAES.h"
#include "CCDES.h"
#include "CCRSA.h"
#include "CCDSA.h"
#include "CCDH.h"
#ifdef WITH_ECC
#include "CCECDH.h"
#include "CCECDSA.h"
#endif
#endif

#include <algorithm>
#include <string.h>

// Initialise the one-and-only instance
std::auto_ptr<CCCryptoFactory> CCCryptoFactory::instance(NULL); 

// Constructor
CCCryptoFactory::CCCryptoFactory()
{
	// Initialise the one-and-only RNG
	rng = new CCRNG();
}

// Destructor
CCCryptoFactory::~CCCryptoFactory()
{
	// Destroy the one-and-only RNG
	///// delete rng;
}

// Return the one-and-only instance
CCCryptoFactory* CCCryptoFactory::i()
{
	if (!instance.get())
	{
		instance = std::auto_ptr<CCCryptoFactory>(new CCCryptoFactory());
	}

	return instance.get();
}

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* CCCryptoFactory::getSymmetricAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

#ifdef notyet /////
	if (!lcAlgo.compare("aes"))
	{
		return new CCAES();
	}
	else if (!lcAlgo.compare("des") || !lcAlgo.compare("3des"))
	{
		return new CCDES();
	}
	else 
	{
#endif
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", lcAlgo.c_str());

		return NULL;
///////	}
}

// Create a concrete instance of an asymmetric algorithm
AsymmetricAlgorithm* CCCryptoFactory::getAsymmetricAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

#ifdef notyet /////
	if (!lcAlgo.compare("rsa"))
	{
		return new CCRSA();
	}
	else if (!lcAlgo.compare("dsa"))
	{
		return new CCDSA();
	}
	else if (!lcAlgo.compare("dh"))
	{
		return new CCDH();
	}
#ifdef WITH_ECC
	else if (!lcAlgo.compare("ecdh"))
	{
		return new CCECDH();
	}
	else if (!lcAlgo.compare("ecdsa"))
	{
		return new CCECDSA();
	}
#endif
	else
	{
#endif
		// No algorithm implementation is available
		ERROR_MSG("Unknown algorithm '%s'", algorithm.c_str());

		return NULL;
///////	}
}

// Create a concrete instance of a hash algorithm
HashAlgorithm* CCCryptoFactory::getHashAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("md5"))
	{
		return new CCMD5();
	}
	else if (!lcAlgo.compare("sha1"))
	{
		return new CCSHA1();
	}
	else if (!lcAlgo.compare("sha224"))
	{
		return new CCSHA224();
	}
	else if (!lcAlgo.compare("sha256"))
	{
		return new CCSHA256();
	}
	else if (!lcAlgo.compare("sha384"))
	{
		return new CCSHA384();
	}
	else if (!lcAlgo.compare("sha512"))
	{
		return new CCSHA512();
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
MacAlgorithm* CCCryptoFactory::getMacAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("hmac-md5"))
	{
		return new CCHMACMD5();
	}
	else if (!lcAlgo.compare("hmac-sha1"))
	{
		return new CCHMACSHA1();
	}
	else if (!lcAlgo.compare("hmac-sha224"))
	{
		return new CCHMACSHA224();
	}
	else if (!lcAlgo.compare("hmac-sha256"))
	{
		return new CCHMACSHA256();
	}
	else if (!lcAlgo.compare("hmac-sha384"))
	{
		return new CCHMACSHA384();
	}
	else if (!lcAlgo.compare("hmac-sha512"))
	{
		return new CCHMACSHA512();
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
RNG* CCCryptoFactory::getRNG(std::string name /* = "default" */)
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

