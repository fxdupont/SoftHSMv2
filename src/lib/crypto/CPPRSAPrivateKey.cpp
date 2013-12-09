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
 CPPRSAPrivateKey.cpp

 Crypto++ RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "CPPRSAPrivateKey.h"
#include "CPPUtil.h"
#include "CPPCryptoFactory.h"
#include <string.h>

// Constructors
CPPRSAPrivateKey::CPPRSAPrivateKey()
{
	rsa = NULL;
}

CPPRSAPrivateKey::CPPRSAPrivateKey(const CryptoPP::RSA::PrivateKey* inRSA)
{
	CPPRSAPrivateKey();

	setFromCPP(inRSA);
}

// Destructor
CPPRSAPrivateKey::~CPPRSAPrivateKey()
{
	delete rsa;
}

// The type
/*static*/ const char* CPPRSAPrivateKey::type = "Crypto++ RSA Private Key";

// Set from Crypto++ representation
void CPPRSAPrivateKey::setFromCPP(const CryptoPP::RSA::PrivateKey* rsa)
{
	ByteString p = CPPUtil::Integer2ByteString(rsa->GetPrime1());
	setP(p);
	ByteString q = CPPUtil::Integer2ByteString(rsa->GetPrime2());
	setQ(q);
	ByteString dp1 = CPPUtil::Integer2ByteString(rsa->GetModPrime1PrivateExponent());
	setDP1(dp1);
	ByteString dq1 = CPPUtil::Integer2ByteString(rsa->GetModPrime2PrivateExponent());
	setDQ1(dq1);
	ByteString pq = CPPUtil::Integer2ByteString(rsa->GetMultiplicativeInverseOfPrime2ModPrime1());
	setPQ(pq);
	ByteString d = CPPUtil::Integer2ByteString(rsa->GetPrivateExponent());
	setD(d);
	ByteString n = CPPUtil::Integer2ByteString(rsa->GetModulus());
	setN(n);
	ByteString e = CPPUtil::Integer2ByteString(rsa->GetPublicExponent());
	setE(e);
}

// Check if the key is of the given type
bool CPPRSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(CPPRSAPrivateKey::type, type);
}

// Setters for the RSA private key components
void CPPRSAPrivateKey::setP(const ByteString& p)
{
	RSAPrivateKey::setP(p);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void CPPRSAPrivateKey::setQ(const ByteString& q)
{
	RSAPrivateKey::setQ(q);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void CPPRSAPrivateKey::setPQ(const ByteString& pq)
{
	RSAPrivateKey::setPQ(pq);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void CPPRSAPrivateKey::setDP1(const ByteString& dp1)
{
	RSAPrivateKey::setDP1(dp1);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void CPPRSAPrivateKey::setDQ1(const ByteString& dq1)
{
	RSAPrivateKey::setDQ1(dq1);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void CPPRSAPrivateKey::setD(const ByteString& d)
{
	RSAPrivateKey::setD(d);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}


// Setters for the RSA public key components
void CPPRSAPrivateKey::setN(const ByteString& n)
{
	RSAPrivateKey::setN(n);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void CPPRSAPrivateKey::setE(const ByteString& e)
{
	RSAPrivateKey::setE(e);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

// Retrieve the Crypto++ representation of the key
CryptoPP::RSA::PrivateKey* CPPRSAPrivateKey::getCPPKey()
{
	if (!rsa)
	{
		createCPPKey();
	}

	return rsa;
}

// Create the Crypto++ representation of the key
void CPPRSAPrivateKey::createCPPKey()
{
	// d and n is not needed, they can be calculated
	if (this->p.size() != 0 &&
	    this->q.size() != 0 &&
	    this->e.size() != 0)
	{
		if (rsa)
		{
			delete rsa;
			rsa = NULL;
		}

		try
		{
			rsa = new CryptoPP::RSA::PrivateKey();
			rsa->Initialize(CPPUtil::byteString2Integer(this->n),
					CPPUtil::byteString2Integer(this->e),
					CPPUtil::byteString2Integer(this->d),
					CPPUtil::byteString2Integer(this->p),
					CPPUtil::byteString2Integer(this->q),
					CPPUtil::byteString2Integer(this->dp1),
					CPPUtil::byteString2Integer(this->dq1),
					CPPUtil::byteString2Integer(this->pq));
		}
		catch (...)
		{
			delete rsa;
			rsa = NULL;

			ERROR_MSG("Could not create the Crypto++ private key");
		}
        }
}
