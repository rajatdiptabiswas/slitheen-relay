/* Name: util.c
 *
 * This file contains safe wrappers for common functions and implementations of
 * data structures
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

#include <stdio.h>
#include <stdlib.h>
#include "util.h"

//malloc macro that exits on error
void *smalloc(size_t size){
    void *ptr = malloc(size);
    if (ptr == NULL){
        fprintf(stderr, "Memory failure. Exiting...\n");
        exit(1);
    }

    return ptr;
}

//calloc macro that exits on error
void *scalloc(size_t nmemb, size_t size){
    void *ptr = calloc(nmemb, size);
    if(ptr == NULL){
        fprintf(stderr, "Memory failure. Exiting...\n");
        exit(1);
    }

    return ptr;
}
