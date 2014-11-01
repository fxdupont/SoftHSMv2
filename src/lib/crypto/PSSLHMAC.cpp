/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation)
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
 PSSLHMAC.cpp

 PolarSSL HMAC implementation
 *****************************************************************************/

#include "config.h"
#include "PSSLHMAC.h"

const md_info_t* PSSLHMACMD5::getHash() const
{
	return md_info_from_type(POLARSSL_MD_MD5);
}

size_t PSSLHMACMD5::getMacSize() const
{
	return 16;
}

const md_info_t* PSSLHMACSHA1::getHash() const
{
	return md_info_from_type(POLARSSL_MD_SHA1);
}

size_t PSSLHMACSHA1::getMacSize() const
{
	return 20;
}

const md_info_t* PSSLHMACSHA224::getHash() const
{
	return md_info_from_type(POLARSSL_MD_SHA224);
}

size_t PSSLHMACSHA224::getMacSize() const
{
	return 28;
}

const md_info_t* PSSLHMACSHA256::getHash() const
{
	return md_info_from_type(POLARSSL_MD_SHA256);
}

size_t PSSLHMACSHA256::getMacSize() const
{
	return 32;
}

const md_info_t* PSSLHMACSHA384::getHash() const
{
	return md_info_from_type(POLARSSL_MD_SHA384);
}

size_t PSSLHMACSHA384::getMacSize() const
{
	return 48;
}

const md_info_t* PSSLHMACSHA512::getHash() const
{
	return md_info_from_type(POLARSSL_MD_SHA512);
}

size_t PSSLHMACSHA512::getMacSize() const
{
	return 64;
}
