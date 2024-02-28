#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "com_h.h"

// context of encrypt & decrypt
EVP_CIPHER_CTX *en, *de;
// For SHA256, block_size = 256-bits, so size(key) = size(iv) = 32 Bytes
unsigned char *key, *iv;

void init_key_iv(){
  key = (unsigned char *) malloc(32);
  iv = (unsigned char *) malloc(32);
  memset(key, 0, 32);
  memset(iv, 0, 32);
}

void set_key(const unsigned char *val_pt){
  memcpy(key, val_pt, 32);
}

void set_iv(const unsigned char *val_pt){
  memcpy(iv, val_pt, 32);
}

void init_AES(){
  en = EVP_CIPHER_CTX_new();
  de = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(en);
  EVP_CIPHER_CTX_init(de);
  EVP_EncryptInit_ex(en, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_DecryptInit_ex(de, EVP_aes_256_cbc(), NULL, key, iv);
}

void aes_encrypt(unsigned char *plaintext, int *len){
    // ensure the upperbound_length
      // AES_BLOCK_SIZE = 32 (Bytes)
  int cipher_len = *len + AES_BLOCK_SIZE, additional_len = 0;
  unsigned char *ciphertext = (unsigned char *) malloc(cipher_len);

  /* re_init */
  EVP_EncryptInit_ex(en, NULL, NULL, NULL, NULL);

  EVP_EncryptUpdate(en, ciphertext, &cipher_len, plaintext, *len);
  EVP_EncryptFinal_ex(en, ciphertext + cipher_len, &additional_len);

  *len = cipher_len + additional_len;
  memcpy(plaintext, ciphertext, *len);
  free(ciphertext);
}

void aes_decrypt(unsigned char *ciphertext, int *len){
    // ensure the upperbound_length
  int plain_len = *len, additional_len = 0;
  unsigned char *plaintext = (unsigned char *) malloc(plain_len);
  
  /* re_init */
  EVP_DecryptInit_ex(de, NULL, NULL, NULL, NULL);

  EVP_DecryptUpdate(de, plaintext, &plain_len, ciphertext, *len);
  EVP_DecryptFinal_ex(de, plaintext + plain_len, &additional_len);

  *len = plain_len + additional_len;
  memcpy(ciphertext, plaintext, *len);
  free(plaintext);
}

void end_AES(){
  free(key);
  free(iv);
}