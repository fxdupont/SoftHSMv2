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
 CPPHMAC.h

 Crypto++ HMAC implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CPPHMAC_H
#define _SOFTHSM_V2_CPPHMAC_H

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "config.h"
#include "CPPMacAlgorithm.h"
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>

class CPPHMACMD5 : public CPPMacAlgorithm
{
public:
	CPPHMACMD5();
};

class CPPHMACSHA1 : public CPPMacAlgorithm
{
public:
	CPPHMACSHA1();
};

class CPPHMACSHA224 : public CPPMacAlgorithm
{
public:
	CPPHMACSHA224();
};

class CPPHMACSHA256 : public CPPMacAlgorithm
{
public:
	CPPHMACSHA256();
};

class CPPHMACSHA384 : public CPPMacAlgorithm
{
public:
	CPPHMACSHA384();
};

class CPPHMACSHA512 : public CPPMacAlgorithm
{
public:
	CPPHMACSHA512();
};

#endif // !_SOFTHSM_V2_CPPHMAC_H

