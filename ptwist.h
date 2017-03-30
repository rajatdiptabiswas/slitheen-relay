
/* Slitheen - a decoy routing system for censorship resistance
 * Copyright (C) 2017 Ian Goldberg (iang@cs.uwaterloo.ca)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 * 
 * If you modify this Program, or any covered work, by linking or combining
 * it with the OpenSSL library (or a modified version of that library), 
 * containing parts covered by the terms of the OpenSSL Licence and the
 * SSLeay license, the licensors of this Program grant you additional
 * permission to convey the resulting work. Corresponding Source for a
 * non-source form of such a combination shall include the source code
 * for the parts of the OpenSSL library used as well as that of the covered
 * work.
 */
#ifndef __PTWIST_H__
#define __PTWIST_H__

#define PTWIST_BITS 168  /* must be a multiple of 8 */
#define PTWIST_BYTES (PTWIST_BITS/8)

#define PTWIST_TAG_BITS 224  /* must be a multiple of 8 */
#define PTWIST_TAG_BYTES (PTWIST_TAG_BITS/8)

#define PTWIST_PUZZLE_STRENGTH 0 /*21*/  /* set to 0 to disable client puzzle */
#define PTWIST_PUZZLE_MASK ((1<<PTWIST_PUZZLE_STRENGTH)-1)

#if PTWIST_PUZZLE_STRENGTH == 0
#define PTWIST_RESP_BITS 0
#else
#define PTWIST_RESP_BITS (PTWIST_PUZZLE_STRENGTH+6)
#endif

#define PTWIST_RESP_BYTES ((PTWIST_RESP_BITS+7)/8)
#define PTWIST_RESP_MASK ((1<<(((PTWIST_RESP_BITS&7)==0)?8:(PTWIST_RESP_BITS&7)))-1)

#define PTWIST_HASH_SHOWBITS (PTWIST_TAG_BITS-PTWIST_BITS-PTWIST_RESP_BITS)
#define PTWIST_HASH_TOTBITS (PTWIST_HASH_SHOWBITS+PTWIST_PUZZLE_STRENGTH)
#define PTWIST_HASH_TOTBYTES ((PTWIST_HASH_TOTBITS+7)/8)
#define PTWIST_HASH_MASK ((1<<(((PTWIST_HASH_TOTBITS&7)==0)?8:(PTWIST_HASH_TOTBITS&7)))-1)

typedef unsigned char byte;

/* Figure out whether there's a point with x-coordinate x on the main
 * curve.  If not, then there's one on the twist curve.  (There are
 * actually two, which are negatives of each other; that doesn't
 * matter.)  Multiply that point by seckey and set out to the
 * x-coordinate of the result. */
void ptwist_pointmul(byte out[PTWIST_BYTES], const byte x[PTWIST_BYTES],
	const byte seckey[PTWIST_BYTES]);

#endif
