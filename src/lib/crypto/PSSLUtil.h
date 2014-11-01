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

#ifndef _SOFTHSM_V2_PSSLUTIL_H
#define _SOFTHSM_V2_PSSLUTIL_H

#include "config.h"
#include "ByteString.h"
#include <polarssl/bignum.h>
#ifdef WITH_ECC
#include <polarssl/ecp.h>
#endif

namespace PSSL
{
	// Convert an PolarSSL multiple-precision integer to a ByteString
	ByteString mpi2ByteString(const mpi& bn);

	// Convert a ByteString to an PolarSSL multiple-precision integer
	void byteString2mpi(const ByteString& byteString, mpi& bn);

#ifdef WITH_ECC
	// Convert an PolarSSL ecp_curve_info to a ByteString
	ByteString grp2ByteString(const ecp_curve_info& grp);

	// Convert a ByteString to an PolarSSL ecp_curve_info
	ecp_curve_info byteString2grp(const ByteString& byteString);

	// Convert an PolarSSL ecp_point to a ByteString
	ByteString pt2ByteString(const ecp_point& pt);

	// Convert a ByteString to an PolarSSL ecp_point in the given ecp_curve_info
	ecp_point byteString2pt(const ByteString& byteString, const ecp_curve_info& grp);
#endif
}

#endif // !_SOFTHSM_V2_PSSLUTIL_H

