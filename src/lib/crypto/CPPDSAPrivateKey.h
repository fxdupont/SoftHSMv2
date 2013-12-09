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
 CPPDSAPrivateKey.h

 Crypto++ DSA private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CPPDSAPRIVATEKEY_H
#define _SOFTHSM_V2_CPPDSAPRIVATEKEY_H

#include "config.h"
#include "DSAPrivateKey.h"
#include <cryptopp/dsa.h>

class CPPDSAPrivateKey : public DSAPrivateKey
{
public:
	// Constructors
	CPPDSAPrivateKey();

	CPPDSAPrivateKey(const CryptoPP::DL_Keys_DSA::PrivateKey* inDSA);
	
	// Destructor
	virtual ~CPPDSAPrivateKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* type);

	// Setters for the DSA private key components
	virtual void setX(const ByteString& x);

	// Setters for the DSA domain parameters
	virtual void setP(const ByteString& p);
	virtual void setQ(const ByteString& q);
	virtual void setG(const ByteString& g);

	// Set from Crypto++ representation
	virtual void setFromCPP(const CryptoPP::DL_Keys_DSA::PrivateKey* dsa);

	// Retrieve the Crypto++ representation of the key
	CryptoPP::DL_Keys_DSA::PrivateKey* getCPPKey();

private:
	// The internal Crypto++ representation
	CryptoPP::DL_Keys_DSA::PrivateKey* dsa;

	// Create the Crypto++ representation of the key
	void createCPPKey();
};

#endif // !_SOFTHSM_V2_CPPDSAPRIVATEKEY_H

