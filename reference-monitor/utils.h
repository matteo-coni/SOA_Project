#ifndef UTILS_H
#define UTILS_H

#define SHA256_DIGEST_SIZE 32
#define MAX_LEN_PWD 32

#include <crypto/hash.h>

char* get_pwd_encrypted(const char *pwd);

#endif //UTIL_H