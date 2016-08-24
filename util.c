/* Name: util.c
 * Author: Cecylia Bocovich <cbocovic@uwaterloo.ca>
 *
 * This file contains helper functions and macros
 */



#include <stdio.h>
#include <stdlib.h>
#include "util.h"

//malloc macro that exits on error
void *emalloc(size_t size){
	void *ptr = malloc(size);
	if (ptr == NULL){
		fprintf(stderr, "Memory failure. Exiting...\n");
		exit(1);
	}
	
	return ptr;
}

//calloc macro that exits on error
void *ecalloc(size_t nmemb, size_t size){
	void *ptr = calloc(nmemb, size);
	if(ptr == NULL){
		fprintf(stderr, "Memory failure. Exiting...\n");
		exit(1);
	}

	return ptr;
}
