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
 BotanECPublicKey.h

 Botan Elliptic Curve public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANECPUBLICKEY_H
#define _SOFTHSM_V2_BOTANECPUBLICKEY_H

#include "config.h"
#include "log.h"
#include "ECPublicKey.h"
#include "BotanUtil.h"
#include <string.h>
#include <botan/ecc_key.h>

template<class ECT>
class BotanECPublicKey : public ECPublicKey
{
public:
	// Constructors
	BotanECPublicKey();
	
	BotanECPublicKey(const ECT* inECKEY);
	
	// Destructor
	virtual ~BotanECPublicKey();

	// Get the base point order length
	virtual unsigned long getOrderLength() const;

	// Setters for the EC public key components
	virtual void setEC(const ByteString& ec);
	virtual void setQ(const ByteString& q);

	// Set from Botan representation
	virtual void setFromBotan(const ECT* eckey);

	// Retrieve the Botan representation of the key
	ECT* getBotanKey();

protected:
	// The internal Botan representation
	ECT* eckey;

	// Create the Botan representation of the key
	void createBotanKey();
};

// Constructors
template<class ECT>
BotanECPublicKey<ECT>::BotanECPublicKey()
{
	eckey = NULL;
}

template<class ECT>
BotanECPublicKey<ECT>::BotanECPublicKey(const ECT* inECKEY)
{
	BotanECPublicKey();

	setFromBotan(inECKEY);
}

// Destructor
template<class ECT>
BotanECPublicKey<ECT>::~BotanECPublicKey()
{
	delete eckey;
}

// Get the base point order length
template<class ECT>
unsigned long BotanECPublicKey<ECT>::getOrderLength() const
{
	try
	{
		Botan::EC_Group group = BotanUtil::byteString2ECGroup(this->ec);
		return group.get_order().bytes();
			
	}
	catch (...)
	{
		ERROR_MSG("Can't get EC group for order length");

		return 0;
	}
}

// Set from Botan representation
template<class ECT>
void BotanECPublicKey<ECT>::setFromBotan(const ECT* eckey)
{
	ByteString ec = BotanUtil::ecGroup2ByteString(eckey->domain());
	setEC(ec);
	ByteString q = BotanUtil::ecPoint2ByteString(eckey->public_point());
	setQ(q);
}

// Setters for the EC public key components
template<class ECT>
void BotanECPublicKey<ECT>::setEC(const ByteString& ec)
{
	ECPublicKey::setEC(ec);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

template<class ECT>
void BotanECPublicKey<ECT>::setQ(const ByteString& q)
{
	ECPublicKey::setQ(q);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Retrieve the Botan representation of the key
template<class ECT>
ECT* BotanECPublicKey<ECT>::getBotanKey()
{
	if (!eckey)
	{
		createBotanKey();
	}

	return eckey;
}
 
// Create the Botan representation of the key
template<class ECT>
void BotanECPublicKey<ECT>::createBotanKey()
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
			Botan::EC_Group group = BotanUtil::byteString2ECGroup(this->ec);
			Botan::PointGFp point = BotanUtil::byteString2ECPoint(this->q, group);
			eckey = new ECT(group, point);
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
#endif // !_SOFTHSM_V2_BOTANECPUBLICKEY_H

