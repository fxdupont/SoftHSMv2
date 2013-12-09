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
 CPPDSAPublicKey.cpp

 Crypto++ DSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "CPPDSAPublicKey.h"
#include "CPPUtil.h"
#include <string.h>

// Constructors
CPPDSAPublicKey::CPPDSAPublicKey()
{
	dsa = NULL;
}

CPPDSAPublicKey::CPPDSAPublicKey(const CryptoPP::DL_Keys_DSA::PublicKey* inDSA)
{
	CPPDSAPublicKey();

	setFromCPP(inDSA);
}

// Destructor
CPPDSAPublicKey::~CPPDSAPublicKey()
{
	delete dsa;
}

// The type
/*static*/ const char* CPPDSAPublicKey::type = "Crypto++ DSA Public Key";

// Set from Crypto++ representation
void CPPDSAPublicKey::setFromCPP(const CryptoPP::DL_Keys_DSA::PublicKey* dsa)
{
	ByteString p = CPPUtil::Integer2ByteString(dsa->GetGroupParameters().GetModulus());
	setP(p);
	ByteString q = CPPUtil::Integer2ByteString(dsa->GetGroupParameters().GetSubgroupOrder());
	setQ(q);
	ByteString g = CPPUtil::Integer2ByteString(dsa->GetGroupParameters().GetSubgroupGenerator());
	setG(g);
	ByteString y = CPPUtil::Integer2ByteString(dsa->GetPublicElement());
	setY(y);
}

// Check if the key is of the given type
bool CPPDSAPublicKey::isOfType(const char* type)
{
	return !strcmp(CPPDSAPublicKey::type, type);
}

// Setters for the DSA public key components
void CPPDSAPublicKey::setP(const ByteString& p)
{
	DSAPublicKey::setP(p);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void CPPDSAPublicKey::setQ(const ByteString& q)
{
	DSAPublicKey::setQ(q);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void CPPDSAPublicKey::setG(const ByteString& g)
{
	DSAPublicKey::setG(g);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void CPPDSAPublicKey::setY(const ByteString& y)
{
	DSAPublicKey::setY(y);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

// Retrieve the Crypto++ representation of the key
CryptoPP::DL_Keys_DSA::PublicKey* CPPDSAPublicKey::getCPPKey()
{
	if (!dsa)
	{
		createCPPKey();
	}

	return dsa;
}
 
// Create the Crypto++ representation of the key
void CPPDSAPublicKey::createCPPKey()
{
	// We actually do not need to check q, since it can be set zero
	if (this->p.size() != 0 &&
	    this->g.size() != 0 &&
	    this->y.size() != 0)
	{
		if (dsa)
		{
			delete dsa;
			dsa = NULL;
		}

		try
		{
			dsa = new CryptoPP::DL_Keys_DSA::PublicKey();
			dsa->Initialize(CPPUtil::byteString2Integer(this->p),
					CPPUtil::byteString2Integer(this->q),
					CPPUtil::byteString2Integer(this->g),
					CPPUtil::byteString2Integer(this->y));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Crypto++ public key");
		}
	}
}
