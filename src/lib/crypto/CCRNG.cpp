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
 CCRNG.cpp

 Botan random number generator class
 *****************************************************************************/

#include "config.h"
#include "CCRNG.h"

#include <fcntl.h>

// Generate random data
bool CCRNG::generateRandom(ByteString& data, const size_t len)
{
	data.wipe(len);

	if (len == 0)
		return true;
	int fd = open("/dev/random", O_RDONLY);

	if (fd == -1)
		return false;

	size_t remain = len;
	size_t done = 0;
	while (remain > 0)
	{
		ssize_t cc = read(fd, &data[done], remain);
		if (cc <= 0)
		{
			(void) close(fd);
			return false;
		}
		done += cc;
		remain -= cc;
	}
	(void) close(fd);
	return true;
}

// Seed the random pool
void CCRNG::seed(ByteString& seedData)
{
	int fd = open("/dev/random", O_WRONLY);
	if (fd == -1)
		return;
	(void) write(fd, seedData.const_byte_str(), seedData.size());
	(void) close(fd);
}
