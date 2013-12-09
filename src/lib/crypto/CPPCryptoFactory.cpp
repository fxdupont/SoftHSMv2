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
 CPPCryptoFactory.cpp

 This is a Crypto++ based cryptographic algorithm factory
 *****************************************************************************/

#include "config.h"
#include "CPPCryptoFactory.h"
#include "CPPAES.h"
#include "CPPDES.h"
#include "CPPMD5.h"
#include "CPPSHA.h"
#include "CPPHMAC.h"
#include "CPPDSA.h"
#include "CPPRSA.h"
#include "CPPDH.h"
#ifdef WITH_ECC
#include "CPPECDH.h"
#include "CPPECDSA.h"
#endif
#include "CPPRNG.h"

// Initialise the one-and-only instance
std::auto_ptr<CPPCryptoFactory> CPPCryptoFactory::instance(NULL);

// Constructor
CPPCryptoFactory::CPPCryptoFactory()
{
	// Initialise the one-and-only RNG
	rng = new CPPRNG();
}

// Destructor
CPPCryptoFactory::~CPPCryptoFactory()
{
	// Destroy the one-and-only RNG
	delete rng;
}

// Return the one-and-only instance
CPPCryptoFactory* CPPCryptoFactory::i()
{
	if (!instance.get())
	{
		instance = std::auto_ptr<CPPCryptoFactory>(new CPPCryptoFactory());
	}

	return instance.get();
}

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* CPPCryptoFactory::getSymmetricAlgorithm(std::string algorithm)
{
        std::string lcAlgo;
        lcAlgo.resize(algorithm.size());
        std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

        if (!lcAlgo.compare("aes"))
        {
                return new CPPAES();
        }
        else if (!lcAlgo.compare("des") || !lcAlgo.compare("3des"))
        {
                return new CPPDES();
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
AsymmetricAlgorithm* CPPCryptoFactory::getAsymmetricAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("rsa"))
	{
		return new CPPRSA();
	}
	else if (!lcAlgo.compare("dsa"))
	{
		return new CPPDSA();
	}
	else if (!lcAlgo.compare("dh"))
	{
		return new CPPDH();
	}
#ifdef WITH_ECC
	else if (!lcAlgo.compare("ecdh"))
	{
		return new CPPECDH();
	}
	// Raw vs SHA: ECDSA is not usable with Crypto++
	else if (!lcAlgo.compare("ecdsa"))
	{
		return new CPPECDSA();
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
HashAlgorithm* CPPCryptoFactory::getHashAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("md5"))
	{
		return new CPPMD5();
	}
	else if (!lcAlgo.compare("sha1"))
	{
		return new CPPSHA1();
	}
	else if (!lcAlgo.compare("sha224"))
	{
		return new CPPSHA224();
	}
	else if (!lcAlgo.compare("sha256"))
	{
		return new CPPSHA256();
	}
	else if (!lcAlgo.compare("sha384"))
	{
		return new CPPSHA384();
	}
	else if (!lcAlgo.compare("sha512"))
	{
		return new CPPSHA512();
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
MacAlgorithm* CPPCryptoFactory::getMacAlgorithm(std::string algorithm)
{
	std::string lcAlgo;
	lcAlgo.resize(algorithm.size());
	std::transform(algorithm.begin(), algorithm.end(), lcAlgo.begin(), tolower);

	if (!lcAlgo.compare("hmac-md5"))
	{
		return new CPPHMACMD5();
	}
	else if (!lcAlgo.compare("hmac-sha1"))
	{
		return new CPPHMACSHA1();
	}
	else if (!lcAlgo.compare("hmac-sha224"))
	{
		return new CPPHMACSHA224();
	}
	else if (!lcAlgo.compare("hmac-sha256"))
	{
		return new CPPHMACSHA256();
	}
	else if (!lcAlgo.compare("hmac-sha384"))
	{
		return new CPPHMACSHA384();
	}
	else if (!lcAlgo.compare("hmac-sha512"))
	{
		return new CPPHMACSHA512();
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
RNG* CPPCryptoFactory::getRNG(std::string name /* = "default" */)
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
