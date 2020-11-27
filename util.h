/* util.h
 *
 * Wrapper functions and data structures
 *
 * Slitheen - a decoy routing system for censorship resistance
 * Copyright (C) 2017 Cecylia Bocovich (cbocovic@uwaterloo.ca)
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

#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
	
/* Defined debugging types */
#ifdef DEBUG_HS
#define DEBUG_HS 1
#else
#define DEBUG_HS 0
#endif

#ifdef DEBUG_CRYPTO
#define DEBUG_CRYPTO 1
#else
#define DEBUG_CRYPTO 0
#endif

#ifdef DEBUG_FLOW
#define DEBUG_FLOW 1
#else
#define DEBUG_FLOW 0
#endif

#ifdef DEBUG_UP
#define DEBUG_UP 1
#else
#define DEBUG_UP 0
#endif

#ifdef DEBUG_PROXY
#define DEBUG_PROXY 1
#else
#define DEBUG_PROXY 0
#endif

#ifdef DEBUG_DOWN
#define DEBUG_DOWN 1
#else
#define DEBUG_DOWN 0
#endif

#ifdef DEBUG_HTTP
#define DEBUG_HTTP 1
#else
#define DEBUG_HTTP 0
#endif

#ifdef EXP_OUS_BANDWIDTH
#define EXP_OUS_BANDWIDTH 1
extern int exp_bytes;
#else
#define EXP_OUS_BANDWIDTH 0
#endif


/* Debugging macros */
#define DEBUG_MSG(type, ...) \
    do { \
        if(type) printf(__VA_ARGS__); \
    } while(0)

#define DEBUG_BYTES(type, ptr, len) \
    do { \
        if(type) { \
            for(int i=0; i < len; i++) printf("%02x ", ptr[i]); \
            printf("\n"); \
        } \
    } while(0)

#define EXPERIMENT(type, len) \
    do { \
        exp_bytes += len; \
        if (exp_bytes > 10000) { \
            fprintf(stderr, "%lu : %d\n", (unsigned long)time(NULL), exp_bytes); \
            exp_bytes = 0; \
        } \
       } while(0)

void *smalloc(size_t size);
void *scalloc(size_t nmemb, size_t size);

#endif /* UTIL_H */
