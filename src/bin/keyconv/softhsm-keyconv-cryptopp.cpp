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
 softhsm-keyconv-cryptopp.cpp

 Code specific for Crypto++
 *****************************************************************************/

#include <config.h>
#define KEYCONV_CPP
#include "softhsm-keyconv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>

// Init Crypto++
void crypto_init()
{
}

// Final Crypto++
void crypto_final()
{
}

// Save the RSA key as a PKCS#8 file
int save_rsa_pkcs8(char* out_path, char* /*file_pin*/, key_material_t* pkey)
{
	int result = 0;
	CryptoPP::RSA::PrivateKey* priv_key = NULL;
	CryptoPP::AutoSeededX917RNG<CryptoPP::AES>* rng = NULL;
	CryptoPP::Integer bigE, bigP, bigQ, bigN, bigD, bigDP, bigDQ, bigCF;

	// See if the key material was found.
	if
	(
		pkey[TAG_MODULUS].size <= 0 ||
		pkey[TAG_PUBEXP].size <= 0 ||
                pkey[TAG_PRIVEXP].size <= 0 ||
		pkey[TAG_PRIME1].size <= 0 ||
		pkey[TAG_PRIME2].size <= 0 ||
		pkey[TAG_EXP1].size <= 0 ||
		pkey[TAG_EXP2].size <= 0 ||
		pkey[TAG_COEFF].size <= 0
	)
	{
		fprintf(stderr, "ERROR: Some parts of the key material is missing in the input file.\n");
		return 1;
	}

	bigE = CryptoPP::Integer((byte*)pkey[TAG_PUBEXP].big,  pkey[TAG_PUBEXP].size);
	bigP = CryptoPP::Integer((byte*)pkey[TAG_PRIME1].big,  pkey[TAG_PRIME1].size);
	bigQ = CryptoPP::Integer((byte*)pkey[TAG_PRIME2].big,  pkey[TAG_PRIME2].size);
	bigN = CryptoPP::Integer((byte*)pkey[TAG_MODULUS].big, pkey[TAG_MODULUS].size);
	bigD = CryptoPP::Integer((byte*)pkey[TAG_PRIVEXP].big, pkey[TAG_PRIVEXP].size);
	bigDP = CryptoPP::Integer((byte*)pkey[TAG_EXP1].big,   pkey[TAG_EXP1].size);
	bigDQ = CryptoPP::Integer((byte*)pkey[TAG_EXP2].big,   pkey[TAG_EXP2].size);
	bigCF = CryptoPP::Integer((byte*)pkey[TAG_COEFF].big,  pkey[TAG_COEFF].size);

	rng = new CryptoPP::AutoSeededX917RNG<CryptoPP::AES>();

	try
	{
		priv_key = new CryptoPP::RSA::PrivateKey();
		priv_key->Initialize(bigN, bigE, bigD, bigP, bigQ, bigDP, bigDQ, bigCF);
		priv_key->Validate(*rng, 3);
	}
	catch(std::exception& e)
	{
		fprintf(stderr, "%s\n", e.what());
		fprintf(stderr, "ERROR: Could not extract the private key from the file.\n");
		delete rng;
		return 1;                                               
	}

	std::ofstream priv_file(out_path);
	if (priv_file == NULL)
	{
		fprintf(stderr, "ERROR: Could not open file for output.\n");
		delete rng;
		delete priv_key;
		return 1;
	}

	try
	{
		// No PIN, DER (vs PEM) output
		CryptoPP::FileSink priv_sink(priv_file);
		priv_key->Save(priv_sink);
		printf("The key has been written to %s\n", out_path);
	}
	catch(std::exception& e)
	{
		fprintf(stderr, "%s\n", e.what());
		fprintf(stderr, "ERROR: Could not write to file.\n");
		result = 1;
	}

	delete rng;
	delete priv_key;
	priv_file.close();

	return result;
}

// Save the DSA key as a PKCS#8 file
int save_dsa_pkcs8(char* out_path, char* /*file_pin*/, key_material_t* pkey)
{
	int result = 0;
	CryptoPP::DL_Keys_DSA::PrivateKey* priv_key = NULL;
	CryptoPP::AutoSeededX917RNG<CryptoPP::AES>* rng = NULL;
	CryptoPP::Integer bigDP, bigDQ, bigDG, bigDX;

	// See if the key material was found.
	if
	(
		pkey[TAG_PRIME].size <= 0 ||
		pkey[TAG_SUBPRIME].size <= 0 ||
		pkey[TAG_BASE].size <= 0 ||
		pkey[TAG_PRIVVAL].size <= 0
	)
	{
		fprintf(stderr, "ERROR: Some parts of the key material is missing in the input file.\n");
		return 1;
	}

	bigDP = CryptoPP::Integer((byte*)pkey[TAG_PRIME].big,    pkey[TAG_PRIME].size);
	bigDQ = CryptoPP::Integer((byte*)pkey[TAG_SUBPRIME].big, pkey[TAG_SUBPRIME].size);
	bigDG = CryptoPP::Integer((byte*)pkey[TAG_BASE].big,     pkey[TAG_BASE].size);
	bigDX = CryptoPP::Integer((byte*)pkey[TAG_PRIVVAL].big,  pkey[TAG_PRIVVAL].size);

	rng = new CryptoPP::AutoSeededX917RNG<CryptoPP::AES>();

	try
	{
		priv_key = new CryptoPP::DL_Keys_DSA::PrivateKey();
		priv_key->Initialize(bigDP, bigDQ, bigDG, bigDX);
		priv_key->Validate(*rng, 3);
	}
	catch (std::exception& e)
	{
		fprintf(stderr, "%s\n", e.what());
		fprintf(stderr, "ERROR: Could not extract the private key from the file.\n");
		delete rng;
		return 1;
	}

	std::ofstream priv_file(out_path);
	if (priv_file == NULL)
	{
		fprintf(stderr, "ERROR: Could not open file for output.\n");
		delete rng;
		delete priv_key;
		return 1;
	}

	try
	{
		CryptoPP::FileSink priv_sink(priv_file);
		priv_key->Save(priv_sink);
		printf("The key has been written to %s\n", out_path);
	}
	catch (std::exception& e)
	{
		fprintf(stderr, "%s\n", e.what());
		fprintf(stderr, "ERROR: Could not write to file.\n");
		result = 1;
	}

	delete rng;
	delete priv_key;
	priv_file.close();

	return result;
}
