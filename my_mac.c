#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "com_h.h"

extern unsigned char *key;
// we share the same key as the AES encryption algorithm
    // since the keys are all 256-bits = 32 Bytes

void get_HMAC_sha256(unsigned char *data, int len, unsigned char *hash_v, int *hash_len_pt){
  HMAC_CTX *ctx = (HMAC_CTX *) malloc(sizeof(HMAC_CTX));
  HMAC_CTX_init(ctx);
  HMAC_Init_ex(ctx, key, 32, EVP_sha256(), NULL);
  HMAC_Update(ctx, data, len);
  HMAC_Final(ctx, hash_v, hash_len_pt);
    // hash_len must be 32
  if (*hash_len_pt != 32){
    printf("Hash Function's return length abnormal!\n");
    exit(5);
  }
  HMAC_CTX_cleanup(ctx);
}

void append_HASH(unsigned char *org_data, int *len_pt){
  int tmp_len = 0;
  get_HMAC_sha256(org_data, *len_pt, org_data + (*len_pt), &tmp_len);
  *len_pt += tmp_len;
    // here tmp_len must be 32
}

int check_HASH_and_recover(unsigned char *data_with_hash, int *len_pt){
  unsigned char *Hash_new = (unsigned char *) malloc(32);
  int tmp_len = 0;
  get_HMAC_sha256(data_with_hash, (*len_pt) - 32, Hash_new, &tmp_len);
  // compare whether the hash value is the same as before
  if (memcmp(Hash_new, data_with_hash + ((*len_pt) - 32), 32) != 0)
    return 0;
  memset(data_with_hash + ((*len_pt) - 32), 0, 32);
  *len_pt -= 32;
  return 1;
}