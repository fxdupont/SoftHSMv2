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
 CPPDHPublicKey.cpp

 Crypto++ Diffie-Hellman public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "CPPDHPublicKey.h"
#include "CPPUtil.h"
#include <string.h>

// Constructors
CPPDHPublicKey::CPPDHPublicKey()
{
	dh = NULL;
}

CPPDHPublicKey::CPPDHPublicKey(const CryptoPP::DL_PublicKey_DH* inDH)
{
	CPPDHPublicKey();

	setFromCPP(inDH);
}

// Destructor
CPPDHPublicKey::~CPPDHPublicKey()
{
	delete dh;
}

// The type
/*static*/ const char* CPPDHPublicKey::type = "Crypto++ DH Public Key";

// Set from Crypto++ representation
void CPPDHPublicKey::setFromCPP(const CryptoPP::DL_PublicKey_DH* dh)
{
	ByteString p = CPPUtil::Integer2ByteString(dh->GetModulus());
	setP(p);
	ByteString g = CPPUtil::Integer2ByteString(dh->GetSubgroupGenerator());
	setG(g);
	ByteString y = CPPUtil::Integer2ByteString(dh->GetPublicElement());
	setY(y);
}

// Check if the key is of the given type
bool CPPDHPublicKey::isOfType(const char* type)
{
	return !strcmp(CPPDHPublicKey::type, type);
}

// Setters for the DH public key components
void CPPDHPublicKey::setP(const ByteString& p)
{
	DHPublicKey::setP(p);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

void CPPDHPublicKey::setG(const ByteString& g)
{
	DHPublicKey::setG(g);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

void CPPDHPublicKey::setY(const ByteString& y)
{
	DHPublicKey::setY(y);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

// Retrieve the Crypto++ representation of the key
CryptoPP::DL_PublicKey_DH* CPPDHPublicKey::getCPPKey()
{
	if (!dh)
	{
		createCPPKey();
	}

	return dh;
}
 
// Create the Crypto++ representation of the key
void CPPDHPublicKey::createCPPKey()
{
	// We actually do not need to check q, since it can be set zero
	if (this->p.size() != 0 && this->y.size() != 0)
	{
		if (dh)
		{
			delete dh;
			dh = NULL;
		}

		try
		{
			dh = new CryptoPP::DL_PublicKey_DH();
			dh->Initialize(CPPUtil::byteString2Integer(this->p),
				       CPPUtil::byteString2Integer(this->g),
				       CPPUtil::byteString2Integer(this->y));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Crypto++ public key");
		}
	}
}
