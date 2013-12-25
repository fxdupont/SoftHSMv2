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
 BotanECPrivateKey.h

 Botan Elliptic Curve private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANECPRIVATEKEY_H
#define _SOFTHSM_V2_BOTANECPRIVATEKEY_H

#include "config.h"
#include "log.h"
#include "ECPrivateKey.h"
#include "BotanCryptoFactory.h"
#include "BotanRNG.h"
#include "BotanUtil.h"
#include <string.h>
#include <botan/pkcs8.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_oid.h>
#include <botan/oids.h>

template<class ECT>
class BotanECPrivateKey : public ECPrivateKey
{
public:
	// Constructors
	BotanECPrivateKey();

	BotanECPrivateKey(const ECT* inECKEY);
	
	// Destructor
	virtual ~BotanECPrivateKey();

	// Get the base point order length
	virtual unsigned long getOrderLength() const;

	// Setters for the EC private key components
	virtual void setD(const ByteString& d);

	// Setters for the EC public key components
	virtual void setEC(const ByteString& ec);

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

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
BotanECPrivateKey<ECT>::BotanECPrivateKey()
{
	eckey = NULL;
}

template<class ECT>
BotanECPrivateKey<ECT>::BotanECPrivateKey(const ECT* inECKEY)
{
	BotanECPrivateKey();

	setFromBotan(inECKEY);
}

// Destructor
template<class ECT>
BotanECPrivateKey<ECT>::~BotanECPrivateKey()
{
	delete eckey;
}

// Get the base point order length
template<class ECT>
unsigned long BotanECPrivateKey<ECT>::getOrderLength() const
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
void BotanECPrivateKey<ECT>::setFromBotan(const ECT* eckey)
{
	ByteString ec = BotanUtil::ecGroup2ByteString(eckey->domain());
	setEC(ec);
	ByteString d = BotanUtil::bigInt2ByteString(eckey->private_value());
	setD(d);
}

// Setters for the EC private key components
template<class ECT>
void BotanECPrivateKey<ECT>::setD(const ByteString& d)
{
	ECPrivateKey::setD(d);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Setters for the EC public key components
template<class ECT>
void BotanECPrivateKey<ECT>::setEC(const ByteString& ec)
{
	ECPrivateKey::setEC(ec);

	if (eckey)
	{
		delete eckey;
		eckey = NULL;
	}
}

// Encode into PKCS#8 DER
template<class ECT>
ByteString BotanECPrivateKey<ECT>::PKCS8Encode()
{
	ByteString der;
	createBotanKey();
	if (eckey == NULL) return der;
	const size_t PKCS8_VERSION = 0;
	// No OID for ECDH
	const Botan::OID oid("1.2.840.10045.2.1");
	// Force EC_DOMPAR_ENC_OID
#if BOTAN_VERSION_MINOR == 11
	const std::vector<Botan::byte> parameters = eckey->domain().DER_encode(Botan::EC_DOMPAR_ENC_OID);
#else
	const Botan::MemoryVector<Botan::byte> parameters = eckey->domain().DER_encode(Botan::EC_DOMPAR_ENC_OID);
#endif
	const Botan::AlgorithmIdentifier alg_id(oid, parameters);
#if BOTAN_VERSION_MINOR == 11
	const Botan::secure_vector<Botan::byte> ber =
#else
	const Botan::SecureVector<Botan::byte> ber =
#endif
		Botan::DER_Encoder()
		.start_cons(Botan::SEQUENCE)
		    .encode(PKCS8_VERSION)
		    .encode(alg_id)
		    .encode(eckey->pkcs8_private_key(), Botan::OCTET_STRING)
		.end_cons()
	    .get_contents();
	der.resize(ber.size());
#if BOTAN_VERSION_MINOR == 11
	memcpy(&der[0], ber.data(), ber.size());
#else
	memcpy(&der[0], ber.begin(), ber.size());
#endif
	return der;
}

// Decode from PKCS#8 BER
template<class ECT>
bool BotanECPrivateKey<ECT>::PKCS8Decode(const ByteString& ber)
{
	Botan::DataSource_Memory source(ber.const_byte_str(), ber.size());
	if (source.end_of_data()) return false;
#if BOTAN_VERSION_MINOR == 11
	Botan::secure_vector<Botan::byte> keydata;
#else
	Botan::SecureVector<Botan::byte> keydata;
#endif
	Botan::AlgorithmIdentifier alg_id;
	const Botan::OID oid("1.2.840.10045.2.1");
	ECT* key = NULL;
	try
	{
		Botan::BER_Decoder(source)
		.start_cons(Botan::SEQUENCE)
			.decode_and_check<size_t>(0, "Unknown PKCS #8 version number")
			.decode(alg_id)
			.decode(keydata, Botan::OCTET_STRING)
			.discard_remaining()
		.end_cons();
		if (keydata.empty())
			throw Botan::Decoding_Error("PKCS #8 private key decoding failed");
		if (alg_id.oid != oid)
		{
			ERROR_MSG("Decoded private key not EC");

			return false;
		}
		key = new ECT(alg_id, keydata);
		if (key == NULL) return false;

		setFromBotan(key);

		delete key;
	}
	catch (std::exception& e)
	{
		ERROR_MSG("Decode failed on %s", e.what());

		return false;
	}

	return true;
}

// Retrieve the Botan representation of the key
template<class ECT>
ECT* BotanECPrivateKey<ECT>::getBotanKey()
{
	if (!eckey)
	{
		createBotanKey();
	}

	return eckey;
}

// Create the Botan representation of the key
template<class ECT>
void BotanECPrivateKey<ECT>::createBotanKey()
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
			BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
			Botan::EC_Group group = BotanUtil::byteString2ECGroup(this->ec);
			eckey = new ECT(*rng->getRNG(),
							group,
							BotanUtil::byteString2bigInt(this->d));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}

#endif // !_SOFTHSM_V2_BOTANECPRIVATEKEY_H
