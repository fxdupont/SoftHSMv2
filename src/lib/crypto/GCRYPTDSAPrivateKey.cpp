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
 GCRYPTDSAPrivateKey.cpp

 libgcrypt DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "GCRYPTDSAPrivateKey.h"
#include "GCRYPTUtil.h"
#include <string.h>

// Constructors
GCRYPTDSAPrivateKey::GCRYPTDSAPrivateKey()
{
	dsa = NULL;
}

GCRYPTDSAPrivateKey::GCRYPTDSAPrivateKey(const gcry_sexp_t inDSA)
{
	GCRYPTDSAPrivateKey();

	setFromGCRYPT(inDSA);
}

// Destructor
GCRYPTDSAPrivateKey::~GCRYPTDSAPrivateKey()
{
	gcry_sexp_release(dsa);
}

// The type
/*static*/ const char* GCRYPTDSAPrivateKey::type = "libgcrypt DSA Private Key";

// Set from libgcrypt representation
void GCRYPTDSAPrivateKey::setFromGCRYPT(const gcry_sexp_t dsa)
{
	gcry_sexp_t px = gcry_sexp_find_token(dsa, "p", 0);
	if (px != NULL)
	{
		gcry_mpi_t pi = gcry_sexp_nth_mpi(px, 1, GCRYMPI_FMT_USG);
		if (pi != NULL)
		{
			ByteString p = GCRYPTUtil::mpi2ByteString(pi);
			setP(p);
		}
		gcry_mpi_release(pi);
	}
	gcry_sexp_release(px);

	gcry_sexp_t qx = gcry_sexp_find_token(dsa, "q", 0);
	if (qx != NULL)
	{
		gcry_mpi_t qi = gcry_sexp_nth_mpi(qx, 1, GCRYMPI_FMT_USG);
		if (qi != NULL)
		{
			ByteString q = GCRYPTUtil::mpi2ByteString(qi);
			setQ(q);
		}
		gcry_mpi_release(qi);
	}
	gcry_sexp_release(qx);

	gcry_sexp_t gx = gcry_sexp_find_token(dsa, "g", 0);
	if (gx != NULL)
	{
		gcry_mpi_t gi = gcry_sexp_nth_mpi(gx, 1, GCRYMPI_FMT_USG);
		if (gi != NULL)
		{
			ByteString g = GCRYPTUtil::mpi2ByteString(gi);
			setG(g);
		}
		gcry_mpi_release(gi);
	}
	gcry_sexp_release(gx);

	gcry_sexp_t xx = gcry_sexp_find_token(dsa, "x", 0);
	if (xx != NULL)
	{
		gcry_mpi_t xi = gcry_sexp_nth_mpi(xx, 1, GCRYMPI_FMT_USG);
		if (xi != NULL)
		{
			ByteString x = GCRYPTUtil::mpi2ByteString(xi);
			setX(x);
		}
		gcry_mpi_release(xi);
	}
	gcry_sexp_release(xx);
}

// Check if the key is of the given type
bool GCRYPTDSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(GCRYPTDSAPrivateKey::type, type);
}

// Setters for the DSA private key components
void GCRYPTDSAPrivateKey::setX(const ByteString& x)
{
	DSAPrivateKey::setX(x);

	gcry_sexp_release(dsa);
	dsa = NULL;
}


// Setters for the DSA domain parameters
void GCRYPTDSAPrivateKey::setP(const ByteString& p)
{
	DSAPrivateKey::setP(p);

	gcry_sexp_release(dsa);
	dsa = NULL;
}

void GCRYPTDSAPrivateKey::setQ(const ByteString& q)
{
	DSAPrivateKey::setQ(q);

	gcry_sexp_release(dsa);
	dsa = NULL;
}

void GCRYPTDSAPrivateKey::setG(const ByteString& g)
{
	DSAPrivateKey::setG(g);

	gcry_sexp_release(dsa);
	dsa = NULL;
}

// Retrieve the libgcrypt representation of the key
gcry_sexp_t GCRYPTDSAPrivateKey::getGCRYPTKey()
{
	if (dsa == NULL)
	{
		createGCRYPTKey();
	}

	return dsa;
}

// Create the libgcrypt representation of the key
void GCRYPTDSAPrivateKey::createGCRYPTKey()
{
	if ((this->p.size() == 0) || (this->q.size() == 0) || (this->g.size() == 0) || (this->x.size() == 0))
		return;

	gcry_sexp_release(dsa);
	gcry_mpi_t pi = GCRYPTUtil::byteString2mpi(this->p);
	gcry_mpi_t qi = GCRYPTUtil::byteString2mpi(this->q);
	gcry_mpi_t gi = GCRYPTUtil::byteString2mpi(this->g);
	gcry_mpi_t xi = GCRYPTUtil::byteString2mpi(this->x);
	gcry_mpi_t yi = gcry_mpi_new(0);
	gcry_mpi_powm(yi, gi, xi, pi);
	gcry_error_t rv = gcry_sexp_build(&dsa, NULL, "(private-key (dsa (p %M) (q %M) (g %M) (y %M) (x %M)))", pi, qi, gi, yi, xi);
	gcry_mpi_release(pi);
	gcry_mpi_release(qi);
	gcry_mpi_release(gi);
	gcry_mpi_release(yi);
	gcry_mpi_release(xi);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("Could not create the private key");
	}
}
