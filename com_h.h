#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28


/*
    Begin of My AES implementation
*/
void init_key_iv();
void set_key(const unsigned char *val_pt);
void set_iv(const unsigned char *val_pt);
void init_AES();
void aes_encrypt(unsigned char *plaintext, int *len);
void aes_decrypt(unsigned char *ciphertext, int *len);
void end_AES();

/*
    Begin of My HMAC-SHA256 implementation
*/
void get_HMAC_sha256(unsigned char *data, int len, unsigned char *hash_v, int *hash_len_pt);
void append_HASH(unsigned char *org_data, int *len_pt);
int check_HASH_and_recover(unsigned char *data_with_hash, int *len_pt);


/*
    Begin of My SSL
*/
void init_ssl_ctx();
void configure_ssl_ctx(const char *crt_path, const char *key_path);
void init_ssl(int socket_num);
int My_SSL_Connect(int cliserv);
void end_ssl();


