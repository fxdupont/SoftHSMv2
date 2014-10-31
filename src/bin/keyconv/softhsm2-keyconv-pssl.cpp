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
 softhsm2-keyconv-pssl.cpp

 Code specific for PolarSSL
 *****************************************************************************/

#include <config.h>
#define KEYCONV_PSSL
#include "softhsm2-keyconv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

#include <polarssl/pk.h>
#include <polarssl/error.h>
#include <polarssl/pem.h>
#include <polarssl/rsa.h>

// Init PolarSSL
void crypto_init()
{
}

// Final PolarSSL
void crypto_final()
{
}

// Save the RSA key as a PKCS#8 file
int save_rsa_pkcs8(char* out_path, char* file_pin, key_material_t* pkey)
{
	fprintf(stderr, "ERROR: PKCS#8 not yet supported by PolarSSL.\n");
	return 1;
}

// Save the DSA key as a PKCS#8 file
int save_dsa_pkcs8(char* out_path, char* file_pin, key_material_t* pkey)
{
	fprintf(stderr, "ERROR: DSA and PKCS#8 not yet supported by PolarSSL.\n");
	return 1;
}
