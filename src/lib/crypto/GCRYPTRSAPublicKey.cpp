/*
 * Copyright (c) 2010 SURFnet bv
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
 GCRYPTRSAPublicKey.cpp

 libgcrypt RSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "GCRYPTRSAPublicKey.h"
#include "GCRYPTUtil.h"
#include <string.h>

// Constructors
GCRYPTRSAPublicKey::GCRYPTRSAPublicKey()
{
	rsa = NULL;
}

GCRYPTRSAPublicKey::GCRYPTRSAPublicKey(const gcry_sexp_t inRSA)
{
	GCRYPTRSAPublicKey();

	setFromGCRYPT(inRSA);
}

// Destructor
GCRYPTRSAPublicKey::~GCRYPTRSAPublicKey()
{
	gcry_sexp_release(rsa);
}

// The type
/*static*/ const char* GCRYPTRSAPublicKey::type = "libgcrypt RSA Public Key";

// Check if the key is of the given type
bool GCRYPTRSAPublicKey::isOfType(const char* type)
{
	return !strcmp(GCRYPTRSAPublicKey::type, type);
}

// Set from libgcrypt representation
void GCRYPTRSAPublicKey::setFromGCRYPT(const gcry_sexp_t rsa)
{
	gcry_sexp_t nx = gcry_sexp_find_token(rsa, "n", 0);
	if (nx != NULL)
	{
		gcry_mpi_t ni = gcry_sexp_nth_mpi(nx, 1, GCRYMPI_FMT_USG);
		if (ni != NULL)
		{
			ByteString n = GCRYPTUtil::mpi2ByteString(ni);
			setN(n);
		}
		gcry_mpi_release(ni);
	}
	gcry_sexp_release(nx);

	gcry_sexp_t ex = gcry_sexp_find_token(rsa, "e", 0);
	if (ex != NULL)
	{
		gcry_mpi_t ei = gcry_sexp_nth_mpi(ex, 1, GCRYMPI_FMT_USG);
		if (ei != NULL)
		{
			ByteString e = GCRYPTUtil::mpi2ByteString(ei);
			setE(e);
		}
		gcry_mpi_release(ei);
	}
	gcry_sexp_release(ex);
}

// Setters for the RSA public key components
void GCRYPTRSAPublicKey::setN(const ByteString& n)
{
	RSAPublicKey::setN(n);

	gcry_sexp_release(rsa);
	rsa = NULL;
}

void GCRYPTRSAPublicKey::setE(const ByteString& e)
{
	RSAPublicKey::setE(e);

	gcry_sexp_release(rsa);
	rsa = NULL;
}

// Retrieve the libgcrypt representation of the key
gcry_sexp_t GCRYPTRSAPublicKey::getGCRYPTKey()
{
	if (rsa == NULL)
	{
		createGCRYPTKey();
	}

	return rsa;
}

// Create the libgcrypt representation of the key
void GCRYPTRSAPublicKey::createGCRYPTKey()
{
	if ((this->n.size() == 0) || (this->e.size() == 0))
		return;

	gcry_sexp_release(rsa);

	gcry_mpi_t ni = GCRYPTUtil::byteString2mpi(this->n);
	gcry_mpi_t ei = GCRYPTUtil::byteString2mpi(this->e);
	gcry_error_t rv = gcry_sexp_build(&rsa, NULL, "(public-key (rsa (n %M) (e %M)))", ni, ei);
	gcry_mpi_release(ni);
	gcry_mpi_release(ei);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("Could not create the public key");
	}
}
