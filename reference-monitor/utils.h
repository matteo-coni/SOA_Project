#ifndef UTILS_H
#define UTILS_H

#define SHA256_DIGEST_SIZE 32
#define MAX_LEN_PWD 32

#include <crypto/hash.h>
#include <linux/fs.h>

char* get_pwd_encrypted(const char *pwd);
char *get_path_from_dentry(struct dentry *dentry); 
int do_sha256(const char *pwd_input, size_t len_pwd, char *output_hash);

#endif //UTIL_H