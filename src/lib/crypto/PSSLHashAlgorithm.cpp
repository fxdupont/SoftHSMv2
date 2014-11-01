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
 PSSLHashAlgorithm.cpp

 Base class for PolarSSL hash algorithm classes
 *****************************************************************************/

#include "config.h"
#include "PSSLHashAlgorithm.h"

// Base constructor
PSSLHashAlgorithm::PSSLHashAlgorithm()
{
	md_init(&ctx);
}

// Destructor
PSSLHashAlgorithm::~PSSLHashAlgorithm()
{
	md_free(&ctx);
}

// Hashing functions
bool PSSLHashAlgorithm::hashInit()
{
	if (!HashAlgorithm::hashInit())
	{
		return false;
	}

	// Initialize the context
	if (md_init_ctx(&ctx, getHash()) != 0)
	{
		ERROR_MSG("md_init_ctx failed");

		md_free(&ctx);

		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);

		return false;
	}

	// Start digesting
	if (md_starts(&ctx) != 0)
	{
		ERROR_MSG("md_starts failed");

		md_free(&ctx);

		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLHashAlgorithm::hashUpdate(const ByteString& data)
{
	if (!HashAlgorithm::hashUpdate(data))
	{
		return false;
	}

	// Continue digesting
	if (data.size() == 0)
	{
		return true;
	}

	if (md_update(&ctx, data.const_byte_str(), data.size()) != 0)
	{
		ERROR_MSG("md_update failed");

		md_free(&ctx);

		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);

		return false;
	}

	return true;
}

bool PSSLHashAlgorithm::hashFinal(ByteString& hashedData)
{
	if (!HashAlgorithm::hashFinal(hashedData))
	{
		return false;
	}

	hashedData.resize(md_get_size(getHash()));

	if (md_finish(&ctx, &hashedData[0]) != 0)
	{
		ERROR_MSG("md_finish failed");

		md_free(&ctx);

		return false;
	}

	md_free(&ctx);

	return true;
}
