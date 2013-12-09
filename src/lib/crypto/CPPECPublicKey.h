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
 CPPECPublicKey.h

 Crypto++ Elliptic Curve public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CPPECPUBLICKEY_H
#define _SOFTHSM_V2_CPPECPUBLICKEY_H

#include "config.h"
#include "ECPublicKey.h"
#include <cryptopp/eccrypto.h>

class CPPECPublicKey : public ECPublicKey
{
public:
	// Constructors
	CPPECPublicKey();
	
	CPPECPublicKey(const CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>* inECKEY);
	
	// Destructor
	virtual ~CPPECPublicKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* type);

	// Get the base point order length
	virtual unsigned long getOrderLength() const;

	// Setters for the EC public key components
	virtual void setEC(const ByteString& ec);
	virtual void setQ(const ByteString& q);

	// Set from Crypto++ representation
	virtual void setFromCPP(const CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>* eckey);

	// Retrieve the Crypto++ representation of the key
	CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>* getCPPKey();

private:
	// The internal Crypto++ representation
	CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>* eckey;

	// Create the Crypto++ representation of the key
	void createCPPKey();
};

#endif // !_SOFTHSM_V2_CPPECPUBLICKEY_H

