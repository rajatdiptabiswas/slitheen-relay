/* until.h by Cecylia Bocovich <cbocovic@uwaterloo.ca>
 *
 * Wrapper functions and data structures
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stddef.h>
#include <stdint.h>

void *emalloc(size_t size);
void *ecalloc(size_t nmemb, size_t size);

//Standard queue data structure
typedef struct element_st {
    void *data;
    struct element_st *next;
} element;

typedef struct queue_st {
    element *first;
    element *last;
} queue;

queue *init_queue();
void enqueue(queue *list, void *data);
void *dequeue(queue *list);
void *peek(queue *list, int32_t n);
void remove_queue(queue *list);

#endif /*_UTIL_H_*/
