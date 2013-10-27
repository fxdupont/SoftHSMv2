/*
 * Copyright (c) 2013 .SE (The Internet Infrastructure Foundation)
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
 CCHMAC.cpp

 CommonCrypto HMAC implementation
 *****************************************************************************/

#include "config.h"
#include "CCHMAC.h"

CCHmacAlgorithm CCHMACMD5::getHash() const
{
	return kCCHmacAlgMD5;
}

size_t CCHMACMD5::getMacSize() const
{
	return CC_MD5_DIGEST_LENGTH;
}

CCHmacAlgorithm CCHMACSHA1::getHash() const
{
	return kCCHmacAlgSHA1;
}

size_t CCHMACSHA1::getMacSize() const
{
	return CC_SHA1_DIGEST_LENGTH;
}

CCHmacAlgorithm CCHMACSHA224::getHash() const
{
	return kCCHmacAlgSHA224;
}

size_t CCHMACSHA224::getMacSize() const
{
	return CC_SHA224_DIGEST_LENGTH;
}

CCHmacAlgorithm CCHMACSHA256::getHash() const
{
	return kCCHmacAlgSHA256;
}

size_t CCHMACSHA256::getMacSize() const
{
	return CC_SHA256_DIGEST_LENGTH;
}

CCHmacAlgorithm CCHMACSHA384::getHash() const
{
	return kCCHmacAlgSHA384;
}

size_t CCHMACSHA384::getMacSize() const
{
	return CC_SHA384_DIGEST_LENGTH;
}

CCHmacAlgorithm CCHMACSHA512::getHash() const
{
	return kCCHmacAlgSHA512;
}

size_t CCHMACSHA512::getMacSize() const
{
	return CC_SHA512_DIGEST_LENGTH;
}
