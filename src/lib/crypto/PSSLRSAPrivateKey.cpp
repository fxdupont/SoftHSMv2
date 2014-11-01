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
 PSSLRSAPrivateKey.cpp

 PolarSSL RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "PSSLRSAPrivateKey.h"
#include "PSSLUtil.h"
#include <string.h>

// Constructors
PSSLRSAPrivateKey::PSSLRSAPrivateKey()
{
	rsa_init(&ctx, RSA_PKCS_V15, POLARSSL_MD_NONE);
}

PSSLRSAPrivateKey::PSSLRSAPrivateKey(const rsa_context& inRSA)
{
	PSSLRSAPrivateKey();

	setFromPSSL(inRSA);
}

// Destructor
PSSLRSAPrivateKey::~PSSLRSAPrivateKey()
{
	rsa_free(&ctx);
}

// The type
/*static*/ const char* PSSLRSAPrivateKey::type = "PolarSSL RSA Private Key";

// Set from PolarSSL representation
void PSSLRSAPrivateKey::setFromPSSL(const rsa_context& rsa)
{
	ByteString p = PSSL::mpi2ByteString(rsa.P);
	setP(p);
	ByteString q = PSSL::mpi2ByteString(rsa.Q);
	setQ(q);
	ByteString dp1 = PSSL::mpi2ByteString(rsa.DP);
	setDP1(dp1);
	ByteString dq1 = PSSL::mpi2ByteString(rsa.DQ);
	setDQ1(dq1);
	ByteString pq = PSSL::mpi2ByteString(rsa.QP);
	setPQ(pq);
	ByteString d = PSSL::mpi2ByteString(rsa.D);
	setD(d);
	ByteString n = PSSL::mpi2ByteString(rsa.N);
	setN(n);
	ByteString e = PSSL::mpi2ByteString(rsa.E);
	setE(e);
}

// Check if the key is of the given type
bool PSSLRSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(PSSLRSAPrivateKey::type, type);
}

// Setters for the RSA private key components
void PSSLRSAPrivateKey::setP(const ByteString& p)
{
	RSAPrivateKey::setP(p);

	PSSL::byteString2mpi(p, ctx.P);
}

void PSSLRSAPrivateKey::setQ(const ByteString& q)
{
	RSAPrivateKey::setQ(q);

	PSSL::byteString2mpi(q, ctx.Q);
}

void PSSLRSAPrivateKey::setPQ(const ByteString& pq)
{
	RSAPrivateKey::setPQ(pq);

	PSSL::byteString2mpi(pq, ctx.QP);
}

void PSSLRSAPrivateKey::setDP1(const ByteString& dp1)
{
	RSAPrivateKey::setDP1(dp1);

	PSSL::byteString2mpi(dp1, ctx.DP);
}

void PSSLRSAPrivateKey::setDQ1(const ByteString& dq1)
{
	RSAPrivateKey::setDQ1(dq1);

	PSSL::byteString2mpi(dq1, ctx.DQ);
}

void PSSLRSAPrivateKey::setD(const ByteString& d)
{
	RSAPrivateKey::setD(d);

	PSSL::byteString2mpi(d, ctx.D);
}


// Setters for the RSA public key components
void PSSLRSAPrivateKey::setN(const ByteString& n)
{
	RSAPrivateKey::setN(n);

	PSSL::byteString2mpi(n, ctx.N);
}

void PSSLRSAPrivateKey::setE(const ByteString& e)
{
	RSAPrivateKey::setE(e);

	PSSL::byteString2mpi(e, ctx.E);
}

// Encode into PKCS#8 DER
ByteString PSSLRSAPrivateKey::PKCS8Encode()
{
	ByteString der;
	// TODO
	return der;
}

// Decode from PKCS#8 BER
bool PSSLRSAPrivateKey::PKCS8Decode(const ByteString& /*ber*/)
{
	// TODO
	return false;
}

// Retrieve the PolarSSL representation of the key
rsa_context* PSSLRSAPrivateKey::getPSSLKey()
{
	return &ctx;
}

