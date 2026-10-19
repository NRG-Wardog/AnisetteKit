// Host-only adapter. This is NOT CommonCrypto or Apple linkage evidence.
#pragma once
#include <openssl/sha.h>
using CC_LONG = unsigned int;
using CC_SHA256_CTX = SHA256_CTX;
inline int CC_SHA256_Init(CC_SHA256_CTX *c) { return SHA256_Init(c); }
inline int CC_SHA256_Update(CC_SHA256_CTX *c, const void *p, CC_LONG n) { return SHA256_Update(c,p,n); }
inline int CC_SHA256_Final(unsigned char *p, CC_SHA256_CTX *c) { return SHA256_Final(p,c); }
