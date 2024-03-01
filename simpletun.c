/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

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

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

int cread_udp(int fd, char *buf, int n, struct sockaddr_in *addr_pt, socklen_t *len_pt){
  
  int nread;

  // printf("Recv from: %x\n", addr_pt->sin_addr.s_addr);

  if((nread = recvfrom(
                fd,
                buf, 
                n, 
                0, 
                (struct sockaddr *)addr_pt, 
                len_pt
              )
      ) < 0
    ){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

int cwrite_udp(int fd, char *buf, int n, struct sockaddr_in *addr_pt, socklen_t *len_pt){
  
  int nread;

  // printf("Send to: %x\n", addr_pt->sin_addr.s_addr);

  if((nread = sendto(
                fd,
                buf, 
                n, 
                0, 
                (struct sockaddr *)addr_pt, 
                sizeof(*addr_pt)
              )
      ) < 0
    ){
    perror("Writing data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

int read_n_udp(int fd, char *buf, int n, struct sockaddr_in *addr_pt, socklen_t *len_pt) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread_udp(fd, buf, left, addr_pt, len_pt))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {

  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd, nread;
  uint16_t nwrite, plength;
//  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1, sock_TCP;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }
  if ((sock_TCP = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }


  /*
    TCP part
  */
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(port);
  if(cliserv==CLIENT){
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);
    if (connect(sock_TCP, (struct sockaddr*) &remote, sizeof(remote)) < 0){
      perror("connect()");
      exit(1);
    }
    net_fd = sock_TCP;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));

  } else{
    if(setsockopt(sock_TCP, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    if (bind(sock_TCP, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    if (listen(sock_TCP, 5) < 0){
      perror("listen()");
      exit(1);
    }
    
    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
      // note that accept means the TCP server will not only provide a brand-new fd, 
        // but a new PORT to support the service as well.
    if ((net_fd = accept(sock_TCP, (struct sockaddr*)&remote, &remotelen)) < 0){
      perror("accept()");
      exit(1);
    }

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }


  /*
    SSL & Key exchange
  */
  init_ssl_ctx();
  printf("%s side initializes ssl context properly\n", cliserv == SERVER ? "Server" : "Client");
  // Both sides need certification
  if (cliserv == SERVER)
    configure_ssl_ctx("server.crt", "server.key");
  else
    configure_ssl_ctx("client.crt", "client.key");
  printf("%s side configures ssl context properly\n", cliserv == SERVER ? "Server" : "Client");
  // pass the previously built TCP connection's fd to init the ssl connection
  init_ssl(net_fd);
  My_SSL_Connect(cliserv);

    // After building the SSL connection, we can directly exchange the key in a secure fashion
  init_key_iv();
  
  if (cliserv == CLIENT){
    RAND_bytes(buffer, 32 * 2); // key + iv
    // set local key and iv
    set_key((unsigned char *)buffer);
    set_iv(((unsigned char *)buffer) + 32);
    printf("Client sets the key/iv OK\n");
    // send to the server
    My_SSL_write(buffer, 32 * 2);
  }
  else{
    // recv msg from client
    My_SSL_read(buffer, 32 * 2);
    // set remote key and iv
    set_key((unsigned char *)buffer);
    set_iv(((unsigned char *)buffer) + 32);
    printf("Server sets the key/iv OK\n");
  }

  // printf("%lx %lx\n", *((unsigned long *)buffer), *((unsigned long *)buffer + 4));

  // clear the buffer
  memset(buffer, 0, 32 * 2);
  // end the ssl session (TODO: break control)
  end_ssl();

  
  /*
   UDP part
  */
  // printf("%x %x %d %d\n", remote.sin_addr.s_addr, local.sin_addr.s_addr, remote.sin_family, remote.sin_port);
  
  if(cliserv==SERVER)
  // recover the original port for the UDP usage
    remote.sin_port = htons(port);

  if(cliserv==CLIENT)
    close(sock_TCP);
  else{
    close(sock_TCP);
    close(net_fd);
  }
  net_fd = sock_fd;
  if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
    perror("setsockopt()");
    exit(1);
  }
  if(bind(sock_fd, (struct sockaddr*)&local, sizeof(local)) < 0){
    perror("bind()");
    exit(1);
  }


  /*
    Here to init the encryption
  */
  init_AES();
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap:
          first read it,
          then encrypt it, together with hashing-append,
          finally write it into the network
      */
      
      // read
      nread = cread(tap_fd, buffer, BUFSIZE);
      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      // encrypt & hash_append
      aes_encrypt(buffer, &nread);
        // nread at most increases 32 here
      append_HASH(buffer, &nread);

      // write into network
      plength = htons(nread);
      nwrite = cwrite_udp(net_fd, (char *)&plength, sizeof(plength), &remote, &remotelen);
      nwrite = cwrite_udp(net_fd, buffer, nread, &remote, &remotelen);
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network:
        first read it
        then check whether the hash is right, together with decrypting,
        finally write it into tun/tap
      */

      int whether_loss_pkg = 0;

      /* Read length */      
      nread = read_n_udp(net_fd, (char *)&plength, sizeof(plength), &remote, &remotelen);
      if(nread == 0) {
        /* ctrl-c at the other end */
        break;
      }
      net2tap++;

      // read
      nread = read_n_udp(net_fd, buffer, ntohs(plength), &remote, &remotelen);
      if (nread != ntohs(plength)){
        printf("Length inconsistent!\n");
        break;
      }
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      // decrypt
      if (check_HASH_and_recover(buffer, &nread) == 0){
        printf("Data's integrity is broken (for some reason)! But we'll ignore this pkg and hope the upper layer (TCP used by the app-layer which use this tunnel) will fix this!\n");
        whether_loss_pkg = 1;
        // exit(4);
      }
      aes_decrypt(buffer, &nread);

      if (whether_loss_pkg == 0){
        /* write into tun/tap */ 
        nwrite = cwrite(tap_fd, buffer, nread);
        do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
      }
      else{
        printf("NET2TAP %lu: %d bytes from network are thrown away...\n", net2tap, nwrite);
      }
    }
  }
  
  end_AES();
  return(0);
}
