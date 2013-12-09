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
 CPPDHPrivateKey.cpp

 Crypto++ Diffie-Hellman private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "CPPDHPrivateKey.h"
#include "CPPUtil.h"
#include <string.h>

// Constructors
CPPDHPrivateKey::CPPDHPrivateKey()
{
	dh = NULL;
}

CPPDHPrivateKey::CPPDHPrivateKey(const CryptoPP::DL_PrivateKey_DH* inDH)
{
	CPPDHPrivateKey();

	setFromCPP(inDH);
}

// Destructor
CPPDHPrivateKey::~CPPDHPrivateKey()
{
	delete dh;
}

// The type
/*static*/ const char* CPPDHPrivateKey::type = "Crypto++ DH Private Key";

// Set from Crypto++ representation
void CPPDHPrivateKey::setFromCPP(const CryptoPP::DL_PrivateKey_DH* dh)
{
	ByteString p = CPPUtil::Integer2ByteString(dh->GetModulus());
	setP(p);
	ByteString g = CPPUtil::Integer2ByteString(dh->GetSubgroupGenerator());
	setG(g);
	ByteString x = CPPUtil::Integer2ByteString(dh->GetPrivateExponent());
	setX(x);
}

// Check if the key is of the given type
bool CPPDHPrivateKey::isOfType(const char* type)
{
	return !strcmp(CPPDHPrivateKey::type, type);
}

// Setters for the DH private key components
void CPPDHPrivateKey::setX(const ByteString& x)
{
	DHPrivateKey::setX(x);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}


// Setters for the DH public key components
void CPPDHPrivateKey::setP(const ByteString& p)
{
	DHPrivateKey::setP(p);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

void CPPDHPrivateKey::setG(const ByteString& g)
{
	DHPrivateKey::setG(g);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

// Retrieve the Crypto++ representation of the key
CryptoPP::DL_PrivateKey_DH* CPPDHPrivateKey::getCPPKey()
{
	if (!dh)
	{
		createCPPKey();
	}

	return dh;
}

// Create the Crypto++ representation of the key
void CPPDHPrivateKey::createCPPKey()
{
	// y is not needed
	if (this->p.size() != 0 &&
	    this->g.size() != 0 &&
	    this->x.size() != 0)
	{
		if (dh)   
		{
			delete dh;
			dh = NULL;
		}

		try
		{
			dh = new CryptoPP::DL_PrivateKey_DH();
			dh->Initialize(CPPUtil::byteString2Integer(this->p),
				       CPPUtil::byteString2Integer(this->g),
				       CPPUtil::byteString2Integer(this->x));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Crypto++ public key");
		}
	}
}
