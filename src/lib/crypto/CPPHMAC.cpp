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
 CPPHMAC.cpp

 Crypto++ HMAC implementation
 *****************************************************************************/

#include "config.h"
#include "CPPHMAC.h"

CPPHMACMD5::CPPHMACMD5()
{
	hmac = new CryptoPP::HMAC<CryptoPP::Weak1::MD5>();
}

CPPHMACSHA1::CPPHMACSHA1()
{
	hmac = new CryptoPP::HMAC<CryptoPP::SHA1>();
}

CPPHMACSHA224::CPPHMACSHA224()
{
	hmac = new CryptoPP::HMAC<CryptoPP::SHA224>();
}

CPPHMACSHA256::CPPHMACSHA256()
{
	hmac = new CryptoPP::HMAC<CryptoPP::SHA256>();
}

CPPHMACSHA384::CPPHMACSHA384()
{
	hmac = new CryptoPP::HMAC<CryptoPP::SHA384>();
}

CPPHMACSHA512::CPPHMACSHA512()
{
	hmac = new CryptoPP::HMAC<CryptoPP::SHA512>();
}
