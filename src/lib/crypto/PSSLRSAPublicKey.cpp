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
 PSSLRSAPublicKey.cpp

 PolarSSL RSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "PSSLRSAPublicKey.h"
#include "PSSLUtil.h"
#include <string.h>

// Constructors
PSSLRSAPublicKey::PSSLRSAPublicKey()
{
	rsa_init(&ctx, RSA_PKCS_V15, POLARSSL_MD_NONE);
}

PSSLRSAPublicKey::PSSLRSAPublicKey(const rsa_context& inRSA)
{
	PSSLRSAPublicKey();

	setFromPSSL(inRSA);
}

// Destructor
PSSLRSAPublicKey::~PSSLRSAPublicKey()
{
	rsa_free(&ctx);
}

// The type
/*static*/ const char* PSSLRSAPublicKey::type = "PolarSSL RSA Public Key";

// Check if the key is of the given type
bool PSSLRSAPublicKey::isOfType(const char* type)
{
	return !strcmp(PSSLRSAPublicKey::type, type);
}

// Set from PolarSSL representation
void PSSLRSAPublicKey::setFromPSSL(const rsa_context& rsa)
{
	ByteString n = PSSL::mpi2ByteString(rsa.N);
	setN(n);
	ByteString e = PSSL::mpi2ByteString(rsa.E);
	setE(e);
}

// Setters for the RSA public key components
void PSSLRSAPublicKey::setN(const ByteString& n)
{
	RSAPublicKey::setN(n);

	PSSL::byteString2mpi(n, ctx.N);
}

void PSSLRSAPublicKey::setE(const ByteString& e)
{
	RSAPublicKey::setE(e);

	PSSL::byteString2mpi(e, ctx.E);
}

// Retrieve the PolarSSL representation of the key
rsa_context* PSSLRSAPublicKey::getPSSLKey()
{
	return &ctx;
}

