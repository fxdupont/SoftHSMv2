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
 BotanDHPrivateKey.cpp

 Botan Diffie-Hellman private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanDHPrivateKey.h"
#include "BotanCryptoFactory.h"
#include "BotanRNG.h"
#include "BotanUtil.h"
#include <string.h>
#include <botan/pkcs8.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>

#if BOTAN_VERSION_MINOR == 11
std::vector<Botan::byte> BotanDH_PrivateKey::public_value() const
#else
Botan::MemoryVector<Botan::byte> BotanDH_PrivateKey::public_value() const
#endif
{
	return this->impl->public_value();
}

// Redefine of DH_PrivateKey constructor with the correct format
BotanDH_PrivateKey::BotanDH_PrivateKey(
			const Botan::AlgorithmIdentifier& alg_id,
#if BOTAN_VERSION_MINOR == 11
			const Botan::secure_vector<Botan::byte>& key_bits,
#else
			const Botan::MemoryRegion<Botan::byte>& key_bits,
#endif
			Botan::RandomNumberGenerator& rng) :
	Botan::DL_Scheme_PrivateKey(alg_id, key_bits, Botan::DL_Group::PKCS3_DH_PARAMETERS)
{
	impl = new Botan::DH_PrivateKey(rng, group, x);
}

BotanDH_PrivateKey::BotanDH_PrivateKey(Botan::RandomNumberGenerator& rng,
				       const Botan::DL_Group& grp,
				       const Botan::BigInt& x_arg)
{
	impl = new Botan::DH_PrivateKey(rng, grp, x_arg);
	group = grp;
	x = x_arg;
	y = impl->get_y();
}

BotanDH_PrivateKey::~BotanDH_PrivateKey()
{
	delete impl;
}

// Constructors
BotanDHPrivateKey::BotanDHPrivateKey()
{
	dh = NULL;
}

BotanDHPrivateKey::BotanDHPrivateKey(const BotanDH_PrivateKey* inDH)
{
	BotanDHPrivateKey();

	setFromBotan(inDH);
}

// Destructor
BotanDHPrivateKey::~BotanDHPrivateKey()
{
	delete dh;
}

// The type
/*static*/ const char* BotanDHPrivateKey::type = "Botan DH Private Key";

// Set from Botan representation
void BotanDHPrivateKey::setFromBotan(const BotanDH_PrivateKey* dh)
{
	ByteString p = BotanUtil::bigInt2ByteString(dh->impl->group_p());
	setP(p);
	ByteString g = BotanUtil::bigInt2ByteString(dh->impl->group_g());
	setG(g);
	ByteString x = BotanUtil::bigInt2ByteString(dh->impl->get_x());
	setX(x);
}

// Check if the key is of the given type
bool BotanDHPrivateKey::isOfType(const char* type)
{
	return !strcmp(BotanDHPrivateKey::type, type);
}

// Setters for the DH private key components
void BotanDHPrivateKey::setX(const ByteString& x)
{
	DHPrivateKey::setX(x);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

// Setters for the DH public key components
void BotanDHPrivateKey::setP(const ByteString& p)
{
	DHPrivateKey::setP(p);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

void BotanDHPrivateKey::setG(const ByteString& g)
{
	DHPrivateKey::setG(g);

	if (dh)
	{
		delete dh;
		dh = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString BotanDHPrivateKey::PKCS8Encode()
{
	ByteString der;
	createBotanKey();
	if (dh == NULL) return der;
	// Force PKCS3_DH_PARAMETERS for p, g and no q.
	const size_t PKCS8_VERSION = 0;
#if BOTAN_VERSION_MINOR == 11
	const std::vector<Botan::byte> parameters = dh->impl->get_domain().DER_encode(Botan::DL_Group::PKCS3_DH_PARAMETERS);
#else
	const Botan::MemoryVector<Botan::byte> parameters = dh->impl->get_domain().DER_encode(Botan::DL_Group::PKCS3_DH_PARAMETERS);
#endif
	const Botan::AlgorithmIdentifier alg_id(dh->impl->get_oid(), parameters);
#if BOTAN_VERSION_MINOR == 11
	const Botan::secure_vector<Botan::byte> ber =
#else
	const Botan::SecureVector<Botan::byte> ber =
#endif
		Botan::DER_Encoder()
		.start_cons(Botan::SEQUENCE)
		    .encode(PKCS8_VERSION)
		    .encode(alg_id)
		    .encode(dh->impl->pkcs8_private_key(), Botan::OCTET_STRING)
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
bool BotanDHPrivateKey::PKCS8Decode(const ByteString& ber)
{
	Botan::DataSource_Memory source(ber.const_byte_str(), ber.size());
	if (source.end_of_data()) return false;
#if BOTAN_VERSION_MINOR == 11
	Botan::secure_vector<Botan::byte> keydata;
#else
	Botan::SecureVector<Botan::byte> keydata;
#endif
	Botan::AlgorithmIdentifier alg_id;
	BotanDH_PrivateKey* key = NULL;
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
		if (Botan::OIDS::lookup(alg_id.oid).compare("DH"))
		{
			ERROR_MSG("Decoded private key not DH");

			return false;
		}
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		key = new BotanDH_PrivateKey(alg_id, keydata, *rng->getRNG());
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
BotanDH_PrivateKey* BotanDHPrivateKey::getBotanKey()
{
	if (!dh)
	{
		createBotanKey();
	}

	return dh;
}

// Create the Botan representation of the key
void BotanDHPrivateKey::createBotanKey()
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
			BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
			dh = new BotanDH_PrivateKey(*rng->getRNG(),
				Botan::DL_Group(BotanUtil::byteString2bigInt(this->p),
						BotanUtil::byteString2bigInt(this->g)),
				BotanUtil::byteString2bigInt(this->x));
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan public key");
		}
	}
}
