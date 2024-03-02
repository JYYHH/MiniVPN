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
  do_debug("ClientTCP: Connected to Server %s\n", inet_ntoa(ntwk->sin_addr));
  return sock_;
}

int server_wait_4_client(int sock_, struct sockaddr_in *ntwk, socklen_t *ntwk_len_pt){
  int ret;
  *ntwk_len_pt = sizeof(*ntwk);
  memset(ntwk, 0, *ntwk_len_pt);
  // note that accept means the TCP server will not only provide a brand-new fd, 
    // but a new PORT to support the service as well.
  if ((ret = accept(sock_, (struct sockaddr*) ntwk, ntwk_len_pt)) < 0){
    perror("accept()");
    exit(1);
  }
  do_debug("ServerTCP: Client connected from %s\n", inet_ntoa(ntwk->sin_addr));

  return ret;
}

  /*
    SSL & Key exchange
  */
void server_in_key_exchange(int net_fd, char *buffer){
  init_ssl_ctx();
  printf("ServerTCP: initializes ssl context properly\n");
  // Both sides need certification, cause in this task we need to verify both's Certification
  configure_ssl_ctx("server.crt", "server.key");
  printf("ServerTCP: configures ssl context properly\n");
  // pass the previously built TCP connection's fd to init the ssl connection
  init_ssl(net_fd);
  int ssl_ret = My_SSL_Connect(SERVER);
  if (ssl_ret == 0){
    printf("ServerTCP: BUILD SSL CONNECTION unsuccessfully, because of the VA verification process\n");
    exit(13);
  }
  // After building the SSL connection, we can directly exchange the key in a secure fashion
  printf("ServerTCP: BUILD SSL CONNECTION SUCCESSFULLY (including verifying the CA of client)\n");
  
// Server: recv the key/iv from the client
  // recv msg from client
  My_SSL_read(buffer, 32 * 2);
  // set remote key and iv
  set_key((unsigned char *)buffer);
  set_iv(((unsigned char *)buffer) + 32);
    // printf("%lx %lx\n", *((unsigned long *)buffer), *((unsigned long *)buffer + 4));
  // clear the buffer
  memset(buffer, 0, 32 * 2);
}

void client_in_key_exchange(int net_fd, char *buffer){
  init_ssl_ctx();
  printf("ClientTCP: initializes ssl context properly\n");
  // Both sides need certification, cause in this task we need to verify both's Certification
  configure_ssl_ctx("client.crt", "client.key");
  printf("ClientTCP: configures ssl context properly\n");
  // pass the previously built TCP connection's fd to init the ssl connection
  init_ssl(net_fd);
  int ssl_ret = My_SSL_Connect(CLIENT);
  if (ssl_ret == 0){
    printf("ClientTCP: BUILD SSL CONNECTION unsuccessfully, because of the VA verification process\n");
    exit(13);
  }
  // After building the SSL connection, we can directly exchange the key in a secure fashion
  printf("ClientTCP: BUILD SSL CONNECTION SUCCESSFULLY (including verifying the CA of server)\n");

// Client: send the key/iv to the server
  RAND_bytes(buffer, 32 * 2); // key + iv
  // set local key and iv
  set_key((unsigned char *)buffer);
  set_iv(((unsigned char *)buffer) + 32);
  // send to the server
  My_SSL_write(buffer, 32 * 2);
  // clear the buffer
  memset(buffer, 0, 32 * 2);
}

void routine_begin(int *pipe_fd){
  init_key_iv();
  if (pipe(pipe_fd) == -1){
    perror("pipe");
    exit(1);
  }
}

void TCP_end(int child_pid, int *pipe_fd){
  end_ssl();
  if (kill(child_pid, SIGKILL) == -1) {
    perror("kill");
    exit(1);
  }
  int status;
  waitpid(child_pid, &status, 0);
  end_AES();
  close(pipe_fd[1]);
  exit(0);
}

void server_guard_process(const int tap_fd, char *buffer){
  mqd_t mq_register = mq_open("/register", O_CREAT | O_RDONLY, 0644, NULL); // waiting for the serverUDP processes' register
  mqd_t mq_fd[33]; // support at most 32 clients
  int virtual_ips[33]; // each clients' virtual ip
  int rg_number = 0, buff_len = 0, dst_ip;
  int maxfd = (tap_fd > mq_register) ? tap_fd : mq_register;

  while(1){
    int ret;
    fd_set rd_set;
    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); 
    FD_SET(mq_register, &rd_set);
    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
    if (ret < 0 && errno == EINTR){
      continue;
    }
    if (ret < 0){
      perror("select()");
      exit(1);
    }
    if (FD_ISSET(tap_fd, &rd_set)){
      // capture an input from tun0
      buff_len = cread(tap_fd, buffer, BUFSIZE);
      dst_ip = *((int *)(buffer + 16));
      printf("SERVER_GUARD: Route a new msg (of size %d) from tap into ServerUDP which serves (%d.%d.%d.%d)\n", 
              buff_len,
              (int)(*(buffer + 16)), 
              (int)(*(buffer + 17)), 
              (int)(*(buffer + 18)), 
              (int)(*(buffer + 19))
            );

      int i = 0;
      while(1){
        i++;
        if (virtual_ips[i] == dst_ip){
          // find the right UDP process
          mq_send(mq_fd[i], buffer, buff_len, 1);
          break;
        }
        if (i >= rg_number){
          // the destination is unknown...
          printf("SERVER_GUARD: unknown destination, just ignore it...\n");
          break;
        }
      }
    }

    if (FD_ISSET(mq_register, &rd_set)){
      // capture a register application from some serverUDP process
      buff_len = mq_receive(mq_register, buffer, BUFSIZE * 5, NULL);
      if (buff_len < 0){
        printf("SERVER_GUARD: error happens when server reading from the register queue\n");
        fprintf(stderr, "Error recv message queue: %s\n", strerror(errno));
        exit(11);
      }
      if (buff_len != 4){
        printf("SERVER_GUARD: ServerUDP process sends the wrong register format!\n");
        exit(12);
      }

      char tmp[27] = "/server_"; // my protocol to find the msg queue for a specific ServerUDP process
      virtual_ips[++rg_number] = *((int *) buffer);
      sprintf(tmp + 8, "%d", virtual_ips[rg_number]);
      mq_fd[rg_number] = mq_open(tmp, O_CREAT | O_WRONLY, 0644, NULL); 

      printf("SERVER_GUARD: ServerUDP which serves virtual IP (%d.%d.%d.%d) registers successfully!\n", 
              (int)(*(buffer + 0)), 
              (int)(*(buffer + 1)), 
              (int)(*(buffer + 2)), 
              (int)(*(buffer + 3))
            );
    }
  }
}