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
 PSSLRNG.cpp

 PolarSSL random number generator class
 *****************************************************************************/

#include "config.h"
#include "PSSLRNG.h"

// Base constructor
PSSLRNG::PSSLRNG()
{
	entropy_init(&ectx);
	ctr_drbg_init(&ctx, entropy_func, &ectx, NULL, 0);
}

// Destructor
PSSLRNG::~PSSLRNG()
{
	ctr_drbg_free(&ctx);
	entropy_free(&ectx);
}

// Generate random data
bool PSSLRNG::generateRandom(ByteString& data, const size_t len)
{
	data.wipe(len);

	if (len == 0)
		return true;
	size_t remain = len;
	unsigned char* p = &data[0];
	while (remain != 0) {
		size_t part = remain;
		if (part > CTR_DRBG_MAX_REQUEST)
			part = CTR_DRBG_MAX_REQUEST;
		if (ctr_drbg_random(&ctx, p, part) != 0)
			return false;
		p += part;
		remain -= part;
	}
	return true;
}

// Seed the random pool
void PSSLRNG::seed(ByteString& seedData)
{
	ctr_drbg_update(&ctx, seedData.byte_str(), seedData.size());
}

// Get context
ctr_drbg_context* PSSLRNG::getCTX()
{
	return &ctx;
}
