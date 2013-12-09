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
 CPPECDH.cpp

 Crypto++ ECDH asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "CPPECDH.h"
#include "CPPECPublicKey.h"
#include "CPPECPrivateKey.h"
#include "CPPUtil.h"
#include <algorithm>
#include <cryptopp/dh.h>

// Return signing function
CryptoPP::PK_Signer* CPPECDH::getSigner() const
{
	ERROR_MSG("ECDH does not support signing");

	return NULL;
}

// Return verifying function
CryptoPP::PK_Verifier* CPPECDH::getVerifier() const
{
	ERROR_MSG("ECDH does not support verifying");

	return NULL;
}


bool CPPECDH::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Get the domain
	CryptoPP::ECDH<CryptoPP::ECP>::Domain* dh = NULL;
	try
	{
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> grp(CPPUtil::byteString2ECGroupOID(((CPPECPrivateKey*) privateKey)->getEC()));
		dh = new CryptoPP::ECDH<CryptoPP::ECP>::Domain(grp);
	}
	catch (...)
	{
		ERROR_MSG("ECDH key generation failed");

		return false;
	}

	// Get keys
	const ByteString priv = ((CPPECPrivateKey*) privateKey)->getD();
	const ByteString pub = ((CPPECPublicKey*) publicKey)->getQ();

	// Derive the secret
	ByteString secret;
	secret.resize(dh->AgreedValueLength());
	// remove the first 2 bytes in the public key
	if (!dh->Agree(&secret[0], priv.const_byte_str(),
		       pub.const_byte_str() + 2))
	{
		ERROR_MSG("Crypto++ ECDH key agreement failed");

		delete dh;

		return false;
	}

	delete dh;

	*ppSymmetricKey = new SymmetricKey(secret.size() * 8);
	if (*ppSymmetricKey == NULL)
	{
		ERROR_MSG("Can't create ECDH secret");

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
#endif
