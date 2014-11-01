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
 PSSLRSAPrivateKey.h

 PolarSSL RSA private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_PSSLRSAPRIVATEKEY_H
#define _SOFTHSM_V2_PSSLRSAPRIVATEKEY_H

#include "config.h"
#include "RSAPrivateKey.h"
#include <polarssl/rsa.h>

class PSSLRSAPrivateKey : public RSAPrivateKey
{
public:
	// Constructors
	PSSLRSAPrivateKey();
	
	PSSLRSAPrivateKey(const rsa_context& inRSA);
	
	// Destructor
	virtual ~PSSLRSAPrivateKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* type);

	// Setters for the RSA private key components
	virtual void setP(const ByteString& p);
	virtual void setQ(const ByteString& q);
	virtual void setPQ(const ByteString& pq);
	virtual void setDP1(const ByteString& dp1);
	virtual void setDQ1(const ByteString& dq1);
	virtual void setD(const ByteString& d);

	// Setters for the RSA public key components
	virtual void setN(const ByteString& n);
	virtual void setE(const ByteString& e);

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

	// Set from PolarSSL representation
	virtual void setFromPSSL(const rsa_context& rsa);

	// Retrieve the PolarSSL representation of the key
	rsa_context* getPSSLKey();

private:
	// The internal PolarSSL representation
	rsa_context ctx;
};

#endif // !_SOFTHSM_V2_PSSLRSAPRIVATEKEY_H

