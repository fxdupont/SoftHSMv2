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
 GCRYPTRSAPrivateKey.cpp

 libgcrypt RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "GCRYPTRSAPrivateKey.h"
#include "GCRYPTUtil.h"
#include <string.h>

// Constructors
GCRYPTRSAPrivateKey::GCRYPTRSAPrivateKey()
{
	rsa = NULL;
}

GCRYPTRSAPrivateKey::GCRYPTRSAPrivateKey(const gcry_sexp_t inRSA)
{
	GCRYPTRSAPrivateKey();

	setFromGCRYPT(inRSA);
}

// Destructor
GCRYPTRSAPrivateKey::~GCRYPTRSAPrivateKey()
{
	gcry_sexp_release(rsa);
}

// The type
/*static*/ const char* GCRYPTRSAPrivateKey::type = "libgcrypt RSA Private Key";

// Set from libgcrypt representation
void GCRYPTRSAPrivateKey::setFromGCRYPT(const gcry_sexp_t rsa)
{
	gcry_sexp_t px = gcry_sexp_find_token(rsa, "p", 0);
	gcry_mpi_t pi = NULL;
	if (px != NULL)
	{
		pi = gcry_sexp_nth_mpi(px, 1, GCRYMPI_FMT_USG);
	}
	gcry_sexp_release(px);

	gcry_sexp_t qx = gcry_sexp_find_token(rsa, "q", 0);
	gcry_mpi_t qi = NULL;
	if (qx != NULL)
	{
		qi = gcry_sexp_nth_mpi(qx, 1, GCRYMPI_FMT_USG);
	}
	gcry_sexp_release(qx);
	if ((pi != NULL) && (qi != NULL) && (gcry_mpi_cmp(qi, pi) > 0))
		gcry_mpi_swap(pi, qi);

	if (pi != NULL)
	{
		ByteString p = GCRYPTUtil::mpi2ByteString(pi);
		setP(p);
	}
	if (qi != NULL)
	{
		ByteString q = GCRYPTUtil::mpi2ByteString(qi);
		setQ(q);
	}

	gcry_sexp_t dx = gcry_sexp_find_token(rsa, "d", 0);
	gcry_mpi_t di = NULL;
	if (dx != NULL)
	{
		di = gcry_sexp_nth_mpi(dx, 1, GCRYMPI_FMT_USG);
	}
	gcry_sexp_release(dx);

	if (di != NULL)
	{
		ByteString d = GCRYPTUtil::mpi2ByteString(di);
		setD(d);
	}

	if ((di != NULL) && (pi != NULL))
	{
		gcry_mpi_t pi_1 = gcry_mpi_new(gcry_mpi_get_nbits(pi));
		gcry_mpi_sub_ui(pi_1, pi, 1UL);
		gcry_mpi_t dmp1 = gcry_mpi_new(0);
		gcry_mpi_mod(dmp1, di, pi_1);
		gcry_mpi_release(pi_1);
		ByteString dp1 = GCRYPTUtil::mpi2ByteString(dmp1);
		gcry_mpi_release(dmp1);
		setDP1(dp1);
	}
	if ((di != NULL) && (qi != NULL))
	{
		gcry_mpi_t qi_1 = gcry_mpi_new(gcry_mpi_get_nbits(qi));
		gcry_mpi_sub_ui(qi_1, qi, 1UL);
		gcry_mpi_t dmq1 = gcry_mpi_new(0);
		gcry_mpi_mod(dmq1, di, qi_1);
		gcry_mpi_release(qi_1);
		ByteString dq1 = GCRYPTUtil::mpi2ByteString(dmq1);
		gcry_mpi_release(dmq1);
		setDQ1(dq1);
	}

	if ((pi != NULL) && (qi != NULL))
	{
		gcry_mpi_t iqmp = gcry_mpi_new(0);
		gcry_mpi_invm(iqmp, qi, pi);
		gcry_sexp_t ux = gcry_sexp_find_token(rsa, "u", 0);
		gcry_mpi_t ui = NULL;
		if (ux != NULL)
			ui = gcry_sexp_nth_mpi(ux, 1, GCRYMPI_FMT_USG);
		gcry_sexp_release(ux);
		if ((ui != NULL) && (gcry_mpi_cmp(iqmp, ui) != 0))
			ERROR_MSG("notice u != q^1 [p]");
		ByteString pq = GCRYPTUtil::mpi2ByteString(iqmp);
		setPQ(pq);
		gcry_mpi_release(iqmp);
		gcry_mpi_release(ui);
	}

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

	gcry_mpi_release(pi);
	gcry_mpi_release(qi);
	gcry_mpi_release(di);
}

// Check if the key is of the given type
bool GCRYPTRSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(GCRYPTRSAPrivateKey::type, type);
}

// Setters for the RSA private key components
void GCRYPTRSAPrivateKey::setP(const ByteString& p)
{
	RSAPrivateKey::setP(p);

	gcry_sexp_release(rsa);
	rsa = NULL;
}

void GCRYPTRSAPrivateKey::setQ(const ByteString& q)
{
	RSAPrivateKey::setQ(q);

	gcry_sexp_release(rsa);
	rsa = NULL;
}

void GCRYPTRSAPrivateKey::setPQ(const ByteString& pq)
{
	RSAPrivateKey::setPQ(pq);

	gcry_sexp_release(rsa);
	rsa = NULL;
}

void GCRYPTRSAPrivateKey::setDP1(const ByteString& dp1)
{
	RSAPrivateKey::setDP1(dp1);

	gcry_sexp_release(rsa);
	rsa = NULL;
}

void GCRYPTRSAPrivateKey::setDQ1(const ByteString& dq1)
{
	RSAPrivateKey::setDQ1(dq1);

	gcry_sexp_release(rsa);
	rsa = NULL;
}

void GCRYPTRSAPrivateKey::setD(const ByteString& d)
{
	RSAPrivateKey::setD(d);

	gcry_sexp_release(rsa);
	rsa = NULL;
}


// Setters for the RSA public key components
void GCRYPTRSAPrivateKey::setN(const ByteString& n)
{
	RSAPrivateKey::setN(n);

	gcry_sexp_release(rsa);
	rsa = NULL;
}

void GCRYPTRSAPrivateKey::setE(const ByteString& e)
{
	RSAPrivateKey::setE(e);

	gcry_sexp_release(rsa);
	rsa = NULL;
}

// Retrieve the libgcrypt representation of the key
gcry_sexp_t GCRYPTRSAPrivateKey::getGCRYPTKey()
{
	if (rsa == NULL)
	{
		createGCRYPTKey();
	}

	return rsa;
}

// Create the libgcrypt representation of the key
void GCRYPTRSAPrivateKey::createGCRYPTKey()
{
	// d and n is not needed, they can be calculated
	if ((this->p.size() == 0) || (this->q.size() == 0) || (this-e.size() == 0))
		return;

	gcry_sexp_release(rsa);

	gcry_mpi_t pi = GCRYPTUtil::byteString2mpi(this->p);
	gcry_mpi_t qi = GCRYPTUtil::byteString2mpi(this->q);
	if (gcry_mpi_cmp(pi, qi) > 0)
		gcry_mpi_swap(pi, qi);
	gcry_mpi_t ei = GCRYPTUtil::byteString2mpi(this->e);
	gcry_mpi_t di = NULL;
	if (this->d.size() == 0)
	{
		gcry_mpi_t pi_1 = gcry_mpi_new(gcry_mpi_get_nbits(pi));
		gcry_mpi_sub_ui(pi_1, pi, 1UL);
		gcry_mpi_t qi_1 = gcry_mpi_new(gcry_mpi_get_nbits(qi));
		gcry_mpi_sub_ui(qi_1, qi, 1UL);
		gcry_mpi_t phi = gcry_mpi_new(gcry_mpi_get_nbits(pi) + gcry_mpi_get_nbits(qi));
		gcry_mpi_mul(phi, pi_1, qi_1);
		gcry_mpi_release(pi_1);
		gcry_mpi_release(qi_1);
		di = gcry_mpi_new(0);
		gcry_mpi_invm(di, ei, phi);
		gcry_mpi_release(phi);
	}
	else
	{
		di = GCRYPTUtil::byteString2mpi(this->d);
	}
	gcry_mpi_t ni = NULL;
	if (this->n.size() == 0)
	{
		ni = gcry_mpi_new(gcry_mpi_get_nbits(pi) + gcry_mpi_get_nbits(qi));
		gcry_mpi_mul(ni, pi, qi);
	}
	else
	{
		ni = GCRYPTUtil::byteString2mpi(this->n);
	}
	gcry_mpi_t ui = gcry_mpi_new(0);
	gcry_mpi_invm(ui, pi, qi);
	if (this->pq.size())
	{
		gcry_mpi_t oi = GCRYPTUtil::byteString2mpi(this->pq);
		if (gcry_mpi_cmp(ui, oi) != 0)
			ERROR_MSG("notice u != p^1 [q]");
		gcry_mpi_release(oi);
	}
	gcry_error_t rv = gcry_sexp_build(&rsa, NULL, "(private-key (rsa (n %M) (e %M) (d %M) (p %M) (q %M) (u %M)))", ni, ei, di, pi, qi, ui);
	gcry_mpi_release(ni);
	gcry_mpi_release(ei);
	gcry_mpi_release(di);
	gcry_mpi_release(pi);
	gcry_mpi_release(qi);
	gcry_mpi_release(ui);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("Could not create the private key");
	}
}

			
