/*
 * Copyright (c) .SE (The Internet Infrastructure Foundation)
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

#include "config.h"
#include "CPPUtil.h"

// Convert a Crypto++ Integer to a ByteString
ByteString CPPUtil::Integer2ByteString(const CryptoPP::Integer& bigInt)
{
	ByteString rv;

	rv.resize(bigInt.ByteCount());
	bigInt.Encode(&rv[0], rv.size());

	return rv;
}

// Convert a ByteString to an Crypto++ Integer
CryptoPP::Integer CPPUtil::byteString2Integer(const ByteString& byteString)
{
	return CryptoPP::Integer(byteString.const_byte_str(), byteString.size());
}

#ifdef WITH_ECC
// Convert a Crypto++ EC group to a ByteString
ByteString CPPUtil::ecGroup2ByteString(const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& ecGroup)
{
	ByteString der;
	// assume than 1024 bytes will be always enough
	der.resize(1024);
	CryptoPP::ArraySink sink(&der[0], der.size());
	ecGroup.DEREncode(sink);
	der.resize(sink.TotalPutLength());
	return der;
}

// Convert a ByteString to a Crypto++ EC group OID
const CryptoPP::OID CPPUtil::byteString2ECGroupOID(const ByteString& byteString)
{
	CryptoPP::ArraySource source(byteString.const_byte_str(), byteString.size(), true);
	return CryptoPP::OID(source);
}

// Convert a Crypto++ EC point to a ByteString
ByteString CPPUtil::ecPoint2ByteString(const CryptoPP::ECPPoint& ecPoint, const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& ecGroup)
{
	ByteString der;
	// assume than 1024 bytes will be always enough
	der.resize(1024);
	CryptoPP::ArraySink sink(&der[0], der.size());
	ecGroup.GetCurve().DEREncodePoint(sink, ecPoint, false);
	der.resize(sink.TotalPutLength());
	return der;
}

// Convert a ByteString to a Crypto++ EC point (or throw)
CryptoPP::ECPPoint CPPUtil::byteString2ecPoint(const ByteString& byteString, const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& ecGroup)
{
	CryptoPP::ECPPoint point;
	if (!ecGroup.GetCurve().DecodePoint(point,
					    byteString.const_byte_str(),
					    byteString.size()))
	{
		CryptoPP::BERDecodeError();
	}
	return point;
}
#endif
