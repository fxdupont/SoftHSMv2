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
 CPPECPublicKey.cpp

 Crypto++ Elliptic Curve public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "CPPECPublicKey.h"
#include "CPPUtil.h"
#include <string.h>

// Constructors
CPPECPublicKey::CPPECPublicKey()
{
	eckey = NULL;
}

CPPECPublicKey::CPPECPublicKey(const CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>* inECKEY)
{
	CPPECPublicKey();

	setFromCPP(inECKEY);
}

// Destructor
CPPECPublicKey::~CPPECPublicKey()
{
	delete eckey;
}

// The type
/*static*/ const char* CPPECPublicKey::type = "Crypto++ EC Public Key";

// Get the base point order length
unsigned long CPPECPublicKey::getOrderLength() const
{
	try
	{
		const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& grp(CPPUtil::byteString2ECGroupOID(this->ec));
		return grp.GetSubgroupOrder().ByteCount();
	}
	catch (...)
	{
		ERROR_MSG("Can't get EC group for order length");

		return 0;
	}
}

// Set from Crypto++ representation
void CPPECPublicKey::setFromCPP(const CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>* eckey)
{
	const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& grp = eckey->GetGroupParameters();
	if (grp.GetEncodeAsOID())
	{
		ByteString ec = CPPUtil::ecGroup2ByteString(grp);
		setEC(ec);
		const CryptoPP::ECPPoint& pt = eckey->GetPublicElement();
		ByteString q = CPPUtil::ecPoint2ByteString(pt, grp);
		setQ(q);
	}
}

// Check if the key is of the given type
bool CPPECPublicKey::isOfType(const char* type)
{
	return !strcmp(CPPECPublicKey::type, type);
}

// Setters for the EC public key components
void CPPECPublicKey::setEC(const ByteString& ec)
{
	ECPublicKey::setEC(ec);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

void CPPECPublicKey::setQ(const ByteString& q)
{
	ECPublicKey::setQ(q);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Retrieve the Crypto++ representation of the key
CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>* CPPECPublicKey::getCPPKey()
{
	if (eckey == NULL)
	{
		createCPPKey();
	}

	return eckey;
}

// Create the Crypto++ representation of the key
void CPPECPublicKey::createCPPKey()
{
	if (this->ec.size() != 0 &&
	    this->q.size() != 0)
	{
		if (eckey)
		{
			delete eckey;
			eckey = NULL;
		}

		try
		{
			CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> grp(CPPUtil::byteString2ECGroupOID(this->ec));
			grp.SetEncodeAsOID(true);
			CryptoPP::ECPPoint pt = CPPUtil::byteString2ecPoint(this->q, grp);
			eckey = new CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>();
			eckey->Initialize(grp, pt);
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Crypto++ public key");

			delete eckey;
			eckey = NULL;
		}
	}
}
#endif
