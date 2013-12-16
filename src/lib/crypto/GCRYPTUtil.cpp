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
 GCRYPTUtil.h

 libgcrypt convenience functions
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "GCRYPTUtil.h"

// Convert an libgcrypt multi precision integer to a ByteString
ByteString GCRYPTUtil::mpi2ByteString(const gcry_mpi_t mpi)
{
	ByteString rv;

	if (mpi != NULL)
	{
		size_t len = 0;
		unsigned char* buffer = NULL;
		gcry_error_t status =  gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &len, mpi);
		if (status != GPG_ERR_NO_ERROR)
			return rv;
		rv.resize(len);
		memcpy(&rv[0], buffer, len);
		gcry_free(buffer);
	}

	return rv;
}

// Convert a ByteString to an libgcrypt multi precision integer
gcry_mpi_t GCRYPTUtil::byteString2mpi(const ByteString& byteString)
{
	gcry_mpi_t mpi = NULL;
	gcry_error_t rv = gcry_mpi_scan(&mpi, GCRYMPI_FMT_USG, byteString.const_byte_str(), byteString.size(), NULL);
	if (rv != GPG_ERR_NO_ERROR)
	{
		gcry_mpi_release(mpi);
		return NULL;
	}
	return mpi;
}

#if 0 // TODO
#ifdef WITH_ECC
// Convert an libgcrypt EC GROUP to a ByteString
ByteString GCRYPTUtil::grp2ByteString(const std::string grp)
{
	ByteString rv;

	if (grp != NULL)
	{
		rv.resize(i2d_ECPKParameters(grp, NULL));
		unsigned char *p = &rv[0];
		i2d_ECPKParameters(grp, &p);
	}

	return rv;
}

// Convert a ByteString to an libgcrypt EC GROUP
std::string GCRYPTUtil::byteString2grp(const ByteString& byteString)
{
	const unsigned char *p = byteString.const_byte_str();
	return d2i_ECPKParameters(NULL, &p, byteString.size());
}

// POINT_CONVERSION_UNCOMPRESSED		0x04

// Convert an libgcrypt EC POINT in the given EC GROUP to a ByteString
ByteString GCRYPTUtil::pt2ByteString(const EC_POINT* pt, const std::string grp)
{
	ByteString rv;

	if (pt != NULL && grp != NULL)
	{
		size_t len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
		if (len > 0x7f)
		{
			ERROR_MSG("Oversized EC point");

			return rv;
		}
		rv.resize(len + 2);
		rv[0] = V_ASN1_OCTET_STRING;
		rv[1] = len & 0x7f;
		EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, &rv[2], len, NULL);
	}

	return rv;
}
#endif
#endif
