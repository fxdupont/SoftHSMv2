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
 CPPECPrivateKey.cpp

 Crypto++ EC private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "CPPECPrivateKey.h"
#include "CPPUtil.h"

// Constructors
CPPECPrivateKey::CPPECPrivateKey()
{
	eckey = NULL;
}

CPPECPrivateKey::CPPECPrivateKey(const CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>* inECKEY)
{
	CPPECPrivateKey();

	setFromCPP(inECKEY);
}

// Destructor
CPPECPrivateKey::~CPPECPrivateKey()
{
	delete eckey;
}

// The type
/*static*/ const char* CPPECPrivateKey::type = "Crypto++ EC Private Key";

// Get the base point order length
unsigned long CPPECPrivateKey::getOrderLength() const
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
void CPPECPrivateKey::setFromCPP(const CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>* eckey)
{
	const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& grp = eckey->GetGroupParameters();
	if (grp.GetEncodeAsOID())
	{
		ByteString ec = CPPUtil::ecGroup2ByteString(grp);
		setEC(ec);
		ByteString d = CPPUtil::Integer2ByteString(eckey->GetPrivateExponent());
		setD(d);
	}
}

// Check if the key is of the given type
bool CPPECPrivateKey::isOfType(const char* type)
{
	return !strcmp(CPPECPrivateKey::type, type);
}

// Setter for the EC private key components
void CPPECPrivateKey::setD(const ByteString& d)
{
	ECPrivateKey::setD(d);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}


// Setter for the EC public key components
void CPPECPrivateKey::setEC(const ByteString& ec)
{
	ECPrivateKey::setEC(ec);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Retrieve the Crypto++ representation of the key
CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>* CPPECPrivateKey::getCPPKey()
{
	if (eckey == NULL)
	{
		createCPPKey();
	}

	return eckey;
}

// Create the Crypto++ representation of the key
void CPPECPrivateKey::createCPPKey()
{
	if (this->ec.size() != 0 &&
	    this->d.size() != 0)
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
			eckey = new CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>();
			eckey->Initialize(grp, CPPUtil::byteString2Integer(this->d));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Crypto++ private key");

			delete eckey;
			eckey = NULL;
		}
	}
}
#endif
