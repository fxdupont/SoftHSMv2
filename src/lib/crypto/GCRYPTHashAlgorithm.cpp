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
 GCRYPTHashAlgorithm.cpp

 Base class for libgcrypt hash algorithm classes
 *****************************************************************************/

#include "config.h"
#include "GCRYPTHashAlgorithm.h"

// Base constructor 
GCRYPTHashAlgorithm::GCRYPTHashAlgorithm()
{
	mdHd = NULL;
}

// Destructor
GCRYPTHashAlgorithm::~GCRYPTHashAlgorithm()
{
	if (mdHd != NULL)
	{
		gcry_md_close(mdHd);
	}
}

// Hashing functions
bool GCRYPTHashAlgorithm::hashInit()
{
	if (!HashAlgorithm::hashInit())
	{
		return false;
	}

	// Initialize the context
	gcry_error_t rv = gcry_md_open(&mdHd, getHash(), 0);
	if (rv != GPG_ERR_NO_ERROR)
	{
		ERROR_MSG("gcry_md_open failed");

		mdHd = NULL;

		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);

		return false;
	}

	return true;
}

bool GCRYPTHashAlgorithm::hashUpdate(const ByteString& data)
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

	gcry_md_write(mdHd, data.const_byte_str(), data.size());

	return true;
}

bool GCRYPTHashAlgorithm::hashFinal(ByteString& hashedData)
{
	if (!HashAlgorithm::hashFinal(hashedData))
	{
		return false;
	}

	hashedData.resize(gcry_md_get_algo_dlen(getHash()));

	unsigned char* digest = gcry_md_read(mdHd, 0);
	if (digest == NULL)
	{
		ERROR_MSG("gcry_md_read failed");

		gcry_md_close(mdHd);
		mdHd = NULL;

		return false;
	}

	memcpy(&hashedData[0], digest, hashedData.size());

	gcry_md_close(mdHd);
	mdHd = NULL;

	return true;
}

