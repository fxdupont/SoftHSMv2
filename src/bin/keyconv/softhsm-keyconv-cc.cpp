/*
 * Copyright (c) 2013 .SE (The Internet Infrastructure Foundation)
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
 softhsm-keyconv-cc.cpp

 Code specific for CommonCrypto
 *****************************************************************************/

#include <config.h>
#define KEYCONV_CC
#include "softhsm-keyconv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

//// TODO #include <CommonCrypto/xxx.h>
#include <stdexcept>
class NotYetImplemented : public std::logic_error
{
public:
	NotYetImplemented(const std::string& msg) : logic_error(msg) {}
};

// Init CommonCrypto
void crypto_init()
{
	//// TODO
	throw NotYetImplemented("CommonCrypto crypto_init()");
}

// Final CommonCrypto
void crypto_final()
{
	//// TODO
}

// Save the RSA key as a PKCS#8 file
int save_rsa_pkcs8(char* out_path, char* file_pin, key_material_t* pkey)
{
	//// TODO
	return 1;
}

// Save the DSA key as a PKCS#8 file
int save_dsa_pkcs8(char* out_path, char* file_pin, key_material_t* pkey)
{
	//// TODO
	return 1;
}
