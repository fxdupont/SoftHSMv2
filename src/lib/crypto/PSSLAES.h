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
 PSSLAES.h

 PolarSSL AES implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_PSSLAES_H
#define _SOFTHSM_V2_PSSLAES_H

#include <polarssl/cipher.h>
#include <string>
#include "config.h"
#include "PSSLSymmetricAlgorithm.h"

class PSSLAES : public PSSLSymmetricAlgorithm
{
public:
	// Destructor
	virtual ~PSSLAES() { }

	// Wrap/Unwrap keys
	virtual bool wrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out);

	virtual bool unwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out);

	// Return the block size
	virtual size_t getBlockSize() const;

protected:
	// Return the right cipher for the operation
	virtual const cipher_info_t* getCipher() const;
};

#endif // !_SOFTHSM_V2_PSSLAES_H
