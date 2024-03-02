#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "com_h.h"

// context of my_ssl connection
SSL_CTX *ctx;
SSL *ssl;

int func_2_call_back(char *buf, int size, int _, void *passphrase) {
  memcpy(buf, (char *)passphrase, size);
  buf[size - 1] = '\0'; // for security reason, although it must originally be \0.
  return strlen(buf);
}

void init_ssl_ctx(){
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  ctx = SSL_CTX_new(SSLv23_method()); // 'SSLv23_method' is a general method for both client and server sides' usage
  const char *passphrase = "cs528pass"; // my passphrase for this project
  SSL_CTX_set_default_passwd_cb(ctx, func_2_call_back);
  SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)passphrase);
}

void configure_ssl_ctx(const char *crt_path, const char *key_path){
  // Below are using local files
  if (SSL_CTX_use_certificate_file(ctx, crt_path, SSL_FILETYPE_PEM) <= 0) {
    printf("Error occurs when loading the crt in path: %s\n", crt_path);
    exit(7);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
    printf("Error occurs when loading the key in path: %s\n", key_path);
    exit(8);
  }

  // Below are asking the certification for the other side of the internet
  // Set up verification mode
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
  // Load the crt of my own CA
  SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
}

void init_ssl(int socket_num){
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, socket_num);
  // printf("Status of SSL_set_fd = %d\n", SSL_set_fd(ssl, socket_num));
  // printf("FD assigned to this SSL: %d / My net_fd: %d\n", SSL_get_fd(ssl), socket_num);
}

int My_SSL_Connect(int cliserv){
  int ret = (cliserv == SERVER ? SSL_accept(ssl) : SSL_connect(ssl));
  if (ret <= 0){
    printf("SSL connection error! \n");
    printf("SSL connection return code: %d\n", ret);
    printf("SSL error type %d\n", SSL_get_error(ssl, ret));
    printf("SSL connection result code: %ld\n", SSL_get_verify_result(ssl));
    exit(6);
  }
  else{
    int verify_result_of_x = (SSL_get_verify_result(ssl) == X509_V_OK);
    // if (cliserv == SERVER)
    //   printf("Whether Server already verified the Certification of Client: %d (1 is yes/ 0 is no)\n", verify_result_of_x);
    // else 
    //   printf("Whether Client already verified the Certification of Server: %d (1 is yes/ 0 is no)\n", verify_result_of_x);
    if (!verify_result_of_x){
      return 0;
    }
  }
  return 1;
}

int My_SSL_write(char *msg, int len){
  return SSL_write(ssl, msg, len);
}

int My_SSL_read(char *msg, int len){
  return SSL_read(ssl, msg, len);
}

void end_ssl(){
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);

  // below is OpenSSL library clean-up
  EVP_cleanup();
  ERR_free_strings();
  CRYPTO_cleanup_all_ex_data();
}

