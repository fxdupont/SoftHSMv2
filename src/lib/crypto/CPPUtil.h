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
 CPPUtil.h

 Crypto++ convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CPPUTIL_H
#define _SOFTHSM_V2_CPPUTIL_H

#include "config.h"
#include "ByteString.h"
#include <cryptopp/integer.h>
#ifdef WITH_ECC
#include <cryptopp/eccrypto.h>
#endif

namespace CPPUtil
{
	// Convert a Crypto++ Integer to a ByteString
	ByteString Integer2ByteString(const CryptoPP::Integer& bigInt);

	// Convert a ByteString to a Crypto++ Integer
	CryptoPP::Integer byteString2Integer(const ByteString& byteString);

#ifdef WITH_ECC
	// Convert a Crypto++ EC group to a ByteString
	ByteString ecGroup2ByteString(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& ecGroup);

	// Convert a ByteString to a Crypto++ EC group OID
	const CryptoPP::OID byteString2ECGroupOID(const ByteString& byteString);

	// Convert a Crypto++ EC Point in the given EC group to a ByteString
	ByteString ecPoint2ByteString(const CryptoPP::ECPPoint& ecPoint, const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& ecGroup);

	// Convert a ByteString to a Crypto++ EC point in the given EC group
	CryptoPP::ECPPoint byteString2ecPoint(const ByteString& byteString, const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& ecGroup);
#endif
}

#endif // !_SOFTHSM_V2_CPPUTIL_H

