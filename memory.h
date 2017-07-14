/*
 * Memory layout and structure
 *
 * Copyright 2017, Kate Gray
 *
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
 */

#ifndef MEMORY_H_
#define MEMORY_H_

// Memory definitions
#define SECRET_SIZE 160/8
#define SHA1_BLOCKSIZE 160/8

// 6 digits
#define HOTP_DIGITS 6
#define HOTP_MODULO 1000000
#define HOTP_FORMAT "%06lu"

#endif /* MEMORY_H_ */
