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
 CPPDSAPrivateKey.cpp

 Crypto++ DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "CPPDSAPrivateKey.h"
#include "CPPUtil.h"
#include <string.h>

// Constructors
CPPDSAPrivateKey::CPPDSAPrivateKey()
{
	dsa = NULL;
}

CPPDSAPrivateKey::CPPDSAPrivateKey(const CryptoPP::DL_Keys_DSA::PrivateKey* inDSA)
{
	CPPDSAPrivateKey();

	setFromCPP(inDSA);
}

// Destructor
CPPDSAPrivateKey::~CPPDSAPrivateKey()
{
	delete dsa;
}

// The type
/*static*/ const char* CPPDSAPrivateKey::type = "Crypto++ DSA Private Key";

// Set from Crypto++ representation
void CPPDSAPrivateKey::setFromCPP(const CryptoPP::DL_Keys_DSA::PrivateKey* dsa)
{
	ByteString p = CPPUtil::Integer2ByteString(dsa->GetGroupParameters().GetModulus());
	setP(p);
	ByteString q = CPPUtil::Integer2ByteString(dsa->GetGroupParameters().GetSubgroupOrder());
	setQ(q);
	ByteString g = CPPUtil::Integer2ByteString(dsa->GetGroupParameters().GetSubgroupGenerator());
	setG(g);
	ByteString x = CPPUtil::Integer2ByteString(dsa->GetPrivateExponent());
	setX(x);
}

// Check if the key is of the given type
bool CPPDSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(CPPDSAPrivateKey::type, type);
}

// Setters for the DSA private key components
void CPPDSAPrivateKey::setX(const ByteString& x)
{
	DSAPrivateKey::setX(x);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}


// Setters for the DSA domain parameters
void CPPDSAPrivateKey::setP(const ByteString& p)
{
	DSAPrivateKey::setP(p);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void CPPDSAPrivateKey::setQ(const ByteString& q)
{
	DSAPrivateKey::setQ(q);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

void CPPDSAPrivateKey::setG(const ByteString& g)
{
	DSAPrivateKey::setG(g);

	if (dsa)
	{
		delete dsa;
		dsa = NULL;
	}
}

// Retrieve the Crypto++ representation of the key
CryptoPP::DL_Keys_DSA::PrivateKey* CPPDSAPrivateKey::getCPPKey()
{
	if (!dsa)
	{
		createCPPKey();
	}

	return dsa;
}

// Create the Crypto++ representation of the key
void CPPDSAPrivateKey::createCPPKey()
{
	// y is not needed
	// Todo: Either q or x is needed. Both is not needed
	if (this->p.size() != 0 &&
	    this->q.size() != 0 &&
	    this->g.size() != 0 &&
	    this->x.size() != 0)
	{
		if (dsa)   
		{
			delete dsa;
			dsa = NULL;
		}

		try
		{
			dsa = new CryptoPP::DL_Keys_DSA::PrivateKey();
			dsa->Initialize(CPPUtil::byteString2Integer(this->p),
					CPPUtil::byteString2Integer(this->q),
					CPPUtil::byteString2Integer(this->g),
					CPPUtil::byteString2Integer(this->x));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Crypto++ private key");
		}
	}
}
