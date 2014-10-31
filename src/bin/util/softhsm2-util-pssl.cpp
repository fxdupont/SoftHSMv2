/*
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation)
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
 softhsm2-util-pssl.cpp

 Code specific for PolarSSL
 *****************************************************************************/

#include <config.h>
#define UTIL_PSSL
#include "softhsm2-util.h"
#include "softhsm2-util-pssl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include <polarssl/pk.h>
#include <polarssl/pem.h>
#include <polarssl/error.h>
#include <polarssl/rsa.h>

// Init PolarSSL
void crypto_init()
{
}

// Final PolarSSL
void crypto_final()
{
}

// Import a key pair from given path
int crypto_import_key_pair
(
	CK_SESSION_HANDLE hSession,
	char* filePath,
	char* filePIN,
	char* label,
	char* objID,
	size_t objIDLen,
	int noPublicKey
)
{
	pk_context* pk = crypto_read_file(filePath, filePIN);
	if (pk == NULL)
	{
		return 1;
	}

	rsa_context* rsa = NULL;

	switch (pk_get_type(pk))
	{
		case POLARSSL_PK_RSA:
			rsa = pk_rsa(*pk);
			break;
		default:
			fprintf(stderr, "ERROR: Cannot handle this algorithm.\n");
			pk_free(pk);
			return 1;
	}

	int result = crypto_save_rsa(hSession, label, objID, objIDLen, noPublicKey, rsa);
	pk_free(pk);
	return result;
}

// Read the key from file
pk_context* crypto_read_file(char* filePath, char* filePIN)
{
	static pk_context pk;

	pk_init(&pk);

	int ret = pk_parse_keyfile(&pk, filePath, filePIN);
	if (ret != 0)
	{
		char errbuf[1024];
		polarssl_strerror(ret, errbuf, sizeof(errbuf));
		fprintf(stderr, "ERROR: failed to load key from file \"%s\": %s\n",
			filePath, errbuf);
		return NULL;
	}

	return &pk;
}

// Save the key data in PKCS#11
int crypto_save_rsa
(
	CK_SESSION_HANDLE hSession,
	char* label,
	char* objID,
	size_t objIDLen,
	int noPublicKey,
	rsa_context* rsa
)
{
	rsa_key_material_t* keyMat = crypto_malloc_rsa(rsa);
	if (!keyMat)
	{
		fprintf(stderr, "ERROR: Could not convert the key material to binary information.\n");
		return 1;
	}

	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE, ckToken = CK_TRUE;
	if (noPublicKey)
	{
		ckToken = CK_FALSE;
	}
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,            &pubClass,    sizeof(pubClass) },
		{ CKA_KEY_TYPE,         &keyType,     sizeof(keyType) },
		{ CKA_LABEL,            label,        strlen(label) },
		{ CKA_ID,               objID,        objIDLen },
		{ CKA_TOKEN,            &ckToken,     sizeof(ckToken) },
		{ CKA_VERIFY,           &ckTrue,      sizeof(ckTrue) },
		{ CKA_ENCRYPT,          &ckFalse,     sizeof(ckFalse) },
		{ CKA_WRAP,             &ckFalse,     sizeof(ckFalse) },
		{ CKA_PUBLIC_EXPONENT,  keyMat->bigE, keyMat->sizeE },
		{ CKA_MODULUS,          keyMat->bigN, keyMat->sizeN }
	};
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS,            &privClass,      sizeof(privClass) },
		{ CKA_KEY_TYPE,         &keyType,        sizeof(keyType) },
		{ CKA_LABEL,            label,           strlen(label) },
		{ CKA_ID,               objID,           objIDLen },
		{ CKA_SIGN,             &ckTrue,         sizeof(ckTrue) },
		{ CKA_DECRYPT,          &ckFalse,        sizeof(ckFalse) },
		{ CKA_UNWRAP,           &ckFalse,        sizeof(ckFalse) },
		{ CKA_SENSITIVE,        &ckTrue,         sizeof(ckTrue) },
		{ CKA_TOKEN,            &ckTrue,         sizeof(ckTrue) },
		{ CKA_PRIVATE,          &ckTrue,         sizeof(ckTrue) },
		{ CKA_EXTRACTABLE,      &ckFalse,        sizeof(ckFalse) },
		{ CKA_PUBLIC_EXPONENT,  keyMat->bigE,    keyMat->sizeE },
		{ CKA_MODULUS,          keyMat->bigN,    keyMat->sizeN },
		{ CKA_PRIVATE_EXPONENT, keyMat->bigD,    keyMat->sizeD },
		{ CKA_PRIME_1,          keyMat->bigP,    keyMat->sizeP },
		{ CKA_PRIME_2,          keyMat->bigQ,    keyMat->sizeQ },
		{ CKA_EXPONENT_1,       keyMat->bigDMP1, keyMat->sizeDMP1 },
		{ CKA_EXPONENT_2,       keyMat->bigDMQ1, keyMat->sizeDMQ1 },
		{ CKA_COEFFICIENT,      keyMat->bigIQMP, keyMat->sizeIQMP }
	};

	CK_OBJECT_HANDLE hKey1, hKey2;
	CK_RV rv = p11->C_CreateObject(hSession, privTemplate, 19, &hKey1);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not save the private key in the token. "
				"Maybe the algorithm is not supported.\n");
		crypto_free_rsa(keyMat);
		return 1;
	}

	rv = p11->C_CreateObject(hSession, pubTemplate, 10, &hKey2);
	crypto_free_rsa(keyMat);

	if (rv != CKR_OK)
	{
		p11->C_DestroyObject(hSession, hKey1);
		fprintf(stderr, "ERROR: Could not save the public key in the token.\n");
		return 1;
	}

	printf("The key pair has been imported.\n");

	return 0;
}

// Convert the PolarSSL key to binary
rsa_key_material_t* crypto_malloc_rsa(rsa_context* rsa)
{
	if (rsa == NULL)
	{
		return NULL;
	}

	rsa_key_material_t* keyMat = (rsa_key_material_t*)malloc(sizeof(rsa_key_material_t));
	if (keyMat == NULL)
	{
		return NULL;
	}

	keyMat->sizeE = mpi_size(&rsa->E);
	keyMat->sizeN = mpi_size(&rsa->N);
	keyMat->sizeD = mpi_size(&rsa->D);
	keyMat->sizeP = mpi_size(&rsa->P);
	keyMat->sizeQ = mpi_size(&rsa->Q);
	keyMat->sizeDMP1 = mpi_size(&rsa->DP);
	keyMat->sizeDMQ1 = mpi_size(&rsa->DQ);
	keyMat->sizeIQMP = mpi_size(&rsa->QP);

	keyMat->bigE = (CK_VOID_PTR)malloc(keyMat->sizeE);
	keyMat->bigN = (CK_VOID_PTR)malloc(keyMat->sizeN);
	keyMat->bigD = (CK_VOID_PTR)malloc(keyMat->sizeD);
	keyMat->bigP = (CK_VOID_PTR)malloc(keyMat->sizeP);
	keyMat->bigQ = (CK_VOID_PTR)malloc(keyMat->sizeQ);
	keyMat->bigDMP1 = (CK_VOID_PTR)malloc(keyMat->sizeDMP1);
	keyMat->bigDMQ1 = (CK_VOID_PTR)malloc(keyMat->sizeDMQ1);
	keyMat->bigIQMP = (CK_VOID_PTR)malloc(keyMat->sizeIQMP);

	if
	(
		!keyMat->bigE ||
		!keyMat->bigN ||
		!keyMat->bigD ||
		!keyMat->bigP ||
		!keyMat->bigQ ||
		!keyMat->bigDMP1 ||
		!keyMat->bigDMQ1 ||
		!keyMat->bigIQMP
	)
	{
		crypto_free_rsa(keyMat);
		return NULL;
	}

	if
	(
		mpi_write_binary(&rsa->E,
				 (unsigned char*)keyMat->bigE,
				 keyMat->sizeE) ||
		mpi_write_binary(&rsa->N,
				 (unsigned char*)keyMat->bigN,
				 keyMat->sizeN) ||
		mpi_write_binary(&rsa->D,
				 (unsigned char*)keyMat->bigD,
				 keyMat->sizeD) ||
		mpi_write_binary(&rsa->P,
				 (unsigned char*)keyMat->bigP,
				 keyMat->sizeP) ||
		mpi_write_binary(&rsa->Q,
				 (unsigned char*)keyMat->bigQ,
				 keyMat->sizeQ) ||
		mpi_write_binary(&rsa->DP,
				 (unsigned char*)keyMat->bigDMP1,
				 keyMat->sizeDMP1) ||
		mpi_write_binary(&rsa->DQ,
				 (unsigned char*)keyMat->bigDMQ1,
				 keyMat->sizeDMQ1) ||
		mpi_write_binary(&rsa->QP,
				 (unsigned char*)keyMat->bigIQMP,
				 keyMat->sizeIQMP)
	)
	{
		crypto_free_rsa(keyMat);
		return NULL;
	}

	return keyMat;
}

// Free the memory of the key
void crypto_free_rsa(rsa_key_material_t* keyMat)
{
	if (keyMat == NULL) return;
	if (keyMat->bigE) free(keyMat->bigE);
	if (keyMat->bigN) free(keyMat->bigN);
	if (keyMat->bigD) free(keyMat->bigD);
	if (keyMat->bigP) free(keyMat->bigP);
	if (keyMat->bigQ) free(keyMat->bigQ);
	if (keyMat->bigDMP1) free(keyMat->bigDMP1);
	if (keyMat->bigDMQ1) free(keyMat->bigDMQ1);
	if (keyMat->bigIQMP) free(keyMat->bigIQMP);
	free(keyMat);
}
