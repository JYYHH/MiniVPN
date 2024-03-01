#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include "com_h.h"

  /*
    TCP part
  */
void set_sockaddr(struct sockaddr_in *ntwk, const int ip_net, const unsigned short int port_net){
  // assume ip_net and port_net are already in network order
  memset(ntwk, 0, sizeof(*ntwk));
  ntwk->sin_family = AF_INET;
  ntwk->sin_addr.s_addr = ip_net;
  ntwk->sin_port = port_net;
}

int client_connect_2_server(int sock_, struct sockaddr_in *ntwk, char *remote_ip, const unsigned short int port){
  set_sockaddr(ntwk, inet_addr(remote_ip), htons(port));
  if (connect(sock_, (struct sockaddr*) ntwk, sizeof(*ntwk)) < 0){
    perror("connect()");
    exit(1);
  }
  do_debug("CLIENT: Connected to server %s\n", inet_ntoa(ntwk->sin_addr));
  return sock_;
}

int server_wait_4_client(int sock_, struct sockaddr_in *ntwk1, struct sockaddr_in *ntwk2, socklen_t *ntwk_len_pt){
  int optval = 1, ret;
  if(setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
    perror("setsockopt()");
    exit(1);
  }
  if (bind(sock_, (struct sockaddr*) ntwk1, sizeof(*ntwk1)) < 0){
    perror("bind()");
    exit(1);
  }
  if (listen(sock_, 5) < 0){
    perror("listen()");
    exit(1);
  }

  *ntwk_len_pt = sizeof(*ntwk2);
  memset(ntwk2, 0, *ntwk_len_pt);
  // note that accept means the TCP server will not only provide a brand-new fd, 
    // but a new PORT to support the service as well.
  if ((ret = accept(sock_, (struct sockaddr*) ntwk2, ntwk_len_pt)) < 0){
    perror("accept()");
    exit(1);
  }
  do_debug("SERVER: Client connected from %s\n", inet_ntoa(ntwk2->sin_addr));

  return ret;
}

  /*
    SSL & Key exchange
  */
void server_in_key_exchange(int net_fd, char *buffer){
  init_ssl_ctx();
  printf("Server side initializes ssl context properly\n");
  // Both sides need certification, cause in this task we need to verify both's Certification
  configure_ssl_ctx("server.crt", "server.key");
  printf("Server side configures ssl context properly\n");
  // pass the previously built TCP connection's fd to init the ssl connection
  init_ssl(net_fd);
  My_SSL_Connect(SERVER);
  // After building the SSL connection, we can directly exchange the key in a secure fashion
  init_key_iv();
  
// Server: recv the key/iv from the client
  // recv msg from client
  My_SSL_read(buffer, 32 * 2);
  // set remote key and iv
  set_key((unsigned char *)buffer);
  set_iv(((unsigned char *)buffer) + 32);
  printf("Server sets the key/iv OK\n");
    // printf("%lx %lx\n", *((unsigned long *)buffer), *((unsigned long *)buffer + 4));
  // clear the buffer
  memset(buffer, 0, 32 * 2);
  // end the ssl session (TODO: break control)
  end_ssl();
}

void client_in_key_exchange(int net_fd, char *buffer){
  init_ssl_ctx();
  printf("Client side initializes ssl context properly\n");
  // Both sides need certification, cause in this task we need to verify both's Certification
  configure_ssl_ctx("client.crt", "client.key");
  printf("Client side configures ssl context properly\n");
  // pass the previously built TCP connection's fd to init the ssl connection
  init_ssl(net_fd);
  My_SSL_Connect(CLIENT);
  // After building the SSL connection, we can directly exchange the key in a secure fashion
  init_key_iv();
  
// Client: send the key/iv to the server
  RAND_bytes(buffer, 32 * 2); // key + iv
  // set local key and iv
  set_key((unsigned char *)buffer);
  set_iv(((unsigned char *)buffer) + 32);
  printf("Client sets the key/iv OK\n");
  // send to the server
  My_SSL_write(buffer, 32 * 2);
  // clear the buffer
  memset(buffer, 0, 32 * 2);
  // end the ssl session (TODO: break control)
  end_ssl();
}
