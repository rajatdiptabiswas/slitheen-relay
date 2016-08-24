/* Name: cryptothread.c
 * Author: Cecylia Bocovich <cbocovic@uwaterloo.ca>
 *
 * This function contains the code necessary for using OpenSSL in a thread-safe
 * manner.
 */


#include <pthread.h>
#include <openssl/crypto.h>
#include "cryptothread.h"

static pthread_mutex_t *crypto_locks;
static long *lock_count;

void init_crypto_locks(void){

	crypto_locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if(!crypto_locks)
		exit(1);
	lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	if(!lock_count)
		exit(1);
	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&(crypto_locks[i]), NULL);
	}

	CRYPTO_THREADID_set_callback(pthreads_thread_id);
	CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void crypto_locks_cleanup(void){
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(crypto_locks[i]));
	}
	OPENSSL_free(crypto_locks);
	OPENSSL_free(lock_count);

}

/** If the mode is CRYPTO_LOCK, the lock indicated by type will be acquired, otherwise it will be released */
void pthreads_locking_callback(int mode, int type, const char *file, int line){

	if(mode & CRYPTO_LOCK){
		pthread_mutex_lock(&(crypto_locks[type]));
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&(crypto_locks[type]));
	}
}

void pthreads_thread_id(CRYPTO_THREADID *tid){
	CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

