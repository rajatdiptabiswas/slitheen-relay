#ifndef __RSERV_H_
#define __RSERV_H_
#include <stdlib.h>
#include "ptwist.h"

int check_tag(byte key[16], const byte privkey[PTWIST_BYTES],
	const byte tag[PTWIST_TAG_BYTES], const byte *context,
	size_t context_len);

#endif /* _RSERV_H_ */
