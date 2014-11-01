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
 PSSLUtil.h

 PolarSSL convenience functions
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "PSSLUtil.h"

// Convert an PolarSSL multiple-precision integer to a ByteString
ByteString PSSL::mpi2ByteString(const mpi& bn)
{
	ByteString rv;

	rv.resize(mpi_size(&bn));
	mpi_write_binary(&bn, &rv[0], rv.size());

	return rv;
}

// Convert a ByteString to an PolarSSL multiple-precision integer
void PSSL::byteString2mpi(const ByteString& byteString, mpi& bn)
{
	mpi_free(&bn);
	mpi_read_binary(&bn, byteString.const_byte_str(), byteString.size());
}

#ifdef WITH_ECC
// Convert an PolarSSL ecp_curve_info to a ByteString
ByteString PSSL::grp2ByteString(const ecp_curve_info& grp)
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

// Convert a ByteString to an PolarSSL ecp_curve_info
ecp_curve_info PSSL::byteString2grp(const ByteString& byteString)
{
	const unsigned char *p = byteString.const_byte_str();
	return d2i_ECPKParameters(NULL, &p, byteString.size());
}

// POINT_CONVERSION_UNCOMPRESSED		0x04

// Convert an PolarSSL ec_point to a ByteString
ByteString PSSL::pt2ByteString(const ecp_point& pt)
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

// Convert a ByteString to an PolarSSL ec_point in the given ecp_curve_info
ecp_point* PSSL::byteString2pt(const ByteString& byteString, const ecp_curve_info& grp)
{
	size_t len = byteString.size();
	if (len < 2)
	{
		ERROR_MSG("Undersized EC point");

		return NULL;
	}
	len -= 2;
	if (len > 0x7f)
	{
		ERROR_MSG("Oversized EC point");

		return NULL;
	}
	ByteString repr = byteString;
	if (repr[0] != V_ASN1_OCTET_STRING)
	{
		ERROR_MSG("EC point tag is not OCTET STRING");

		return NULL;
	}
	if (repr[1] != len)
	{
		if (repr[1] < len)
		{
			ERROR_MSG("Underrun EC point");
		}
		else
		{
			ERROR_MSG("Overrun EC point");
		}

		return NULL;
	}

	EC_POINT* pt = EC_POINT_new(grp);
	if (!EC_POINT_oct2point(grp, pt, &repr[2], len, NULL))
	{
		EC_POINT_free(pt);
		return NULL;
	}
	return pt;
}
#endif
