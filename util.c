/* Name: util.c
 * Author: Cecylia Bocovich <cbocovic@uwaterloo.ca>
 *
 * This file contains safe wrappers for common functions and implementations of
 * data structures
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

/**
 * Initializes a generic queue structure
 */

queue *init_queue(){
    queue *new_queue = emalloc(sizeof(queue));

    new_queue->first = NULL;
    new_queue->last = NULL;

    return new_queue;
}

/**
 * Function to append a struct to the end of a list
 */
void enqueue(queue *list, void *data){
    element *new_elem = emalloc(sizeof(element));
    new_elem->data = data;
    new_elem->next = NULL;

    if(list->first == NULL){
        list->first = new_elem;
        list->last = new_elem;
    } else {
        list->last->next = new_elem;
        list->last = new_elem;
    }

}

/**
 * Removes and returns the first element from the front of the list. Returns NULL
 * if list is empty
 */
void *dequeue(queue *list){

    if(list->first == NULL){
        return NULL;
    }

    void *data = list->first->data;
    element *target =list->first;
    
    list->first = target->next;

    free(target);

    return data;
}

/**
 * Returns the nth element of the queue (as provided)
 *
 * An input of -1 peeks at last element
 *
 * Returns data on success, NULL on failure
 */

void *peek(queue *list, int32_t n){
    
    int32_t i;
    element *target = list->first;

    if(n == -1){
        target = list->last;
    }

    for(i=0; (i< n) && (target == NULL); i++){
        target = target->next;
    }

    if(target == NULL){
        return NULL;
    } else {
        return target->data;
    }

}

/**
 * Removes (frees the data in) all elements from the list and then frees the list itself
 */
void remove_queue(queue *list){

    void *data = dequeue(list);
    while(data != NULL){
        free(data);
        data = dequeue(list);
    
    }
    
    free(list);
}

