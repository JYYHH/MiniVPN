#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

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



