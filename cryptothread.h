#ifndef _CRYPTOTHREAD_H_
#define _CRYPTOTHREAD_H_

#include <openssl/crypto.h>
void init_crypto_locks(void);
void crypto_locks_cleanup(void);

void pthreads_thread_id(CRYPTO_THREADID *tid);
void pthreads_locking_callback(int mode, int type, const char *file, int line);
#endif /* _CRYPTOTHREAD_H_ */
