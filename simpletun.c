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
#include <sys/wait.h>
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
      return 0;      
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

extern unsigned char *key, *iv;

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
  char virtual_ip[16] = "";
  unsigned short int port = PORT;
  unsigned short int port4udp = PORTUDP;
  int sock_fd, net_fd, optval = 1, sock_TCP;
  socklen_t remotelen = 0; // need initialization...
    // which bugs me over 6 hours...
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  int virtual_ip_number = 0; 
    // This is used for server to distinguish different clients
    // in network order

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahdv:")) > 0){
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
      case 'v':
        // only will be used by the client to specify it's own virtual ip
        strncpy(virtual_ip,optarg,15);
        virtual_ip_number = inet_addr(virtual_ip);
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
  if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  int pipefd[2]; // be used to Communicate between TCP process and UDP process

  if (cliserv == SERVER){
  // ------------------------ Server Routine begins ----------------------------------
    if (fork() > 0){
      // Server guard: register of tunnel process & transfer tap's msg
        // Server side, using "POSIX Message Queue" to transfer msg from tun into UDP subprocesses
        // Also listen for the register
      server_guard_process(tap_fd, buffer);
    }

    // build a TCP socket
    if ((sock_TCP = socket(AF_INET, SOCK_STREAM, 0)) < 0){
      perror("socket()");
      exit(1);
    }
    set_sockaddr(&local, htonl(INADDR_ANY), htons(port));
    if(setsockopt(sock_TCP, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    // bind and listen
    if (bind(sock_TCP, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    if (listen(sock_TCP, 5) < 0){
      perror("listen()");
      exit(1);
    }

    // Waiting for the client coming
    while(net_fd = server_wait_4_client(sock_TCP, &remote, &remotelen)){
      if (fork() == 0)
        break; // child process break, father process stay in while to continue listening
      // the father process will be always here, unless we send signals to it
        // but the TCP and UDP subprocesses will be quited automatically if we terminate the client
      port4udp--; // this ensure the udp ports won't collide..
    }

    // Now here, net_fd and remote are both of the present connected client
    // And all below are the resources which the server needs to recycle (when client crashes)...
    close(sock_TCP); // this is serving process, does not need to listen
    routine_begin(pipefd);
    int child_pid = fork();
    if (child_pid > 0){
    // ------------------------ Server TCP begins ----------------------------------
      // we are in father process
        // close the read pipe fd, cause the father does not need the child's feedback (lol)
      close(pipefd[0]);
      // exchange key
      server_in_key_exchange(net_fd, buffer);
        // tell the ServerUDP the key/iv
      printf("ServerTCP: Sets the key/iv = %lx/%lx OK\n", *((long int *)key), *((long int *)iv));
      cwrite(pipefd[1], (char *)key, 32);
      cwrite(pipefd[1], (char *)iv, 32);
        // tell the ServerUDP the port_number
      cwrite(pipefd[1], (char *)&port4udp, 2);
        // tell the ClientTCP the port_number
      My_SSL_write((char *)&port4udp, 2);
        // recv the ClientTCP's virtual ip address
      My_SSL_read((char *)&virtual_ip_number, 4);
        // tell the ServerUDP the virtual ip address
      cwrite(pipefd[1], (char *)&virtual_ip_number, 4);
      
      // Server Key-IV Alter
      while(1){
        if (My_SSL_read((char *)key, 32) <= 0){
          // Client is down
          break;
        }
        My_SSL_read((char *)iv, 32);
        cwrite(pipefd[1], (char *)key, 32);
        cwrite(pipefd[1], (char *)iv, 32);
        printf("ServerTCP: RE-Sets the key/iv = %lx/%lx OK\n", *((long int *)key), *((long int *)iv));
      }

    // ------------------------ Server TCP ends ----------------------------------
      TCP_end(child_pid, pipefd);
    }
  // ------------------------ Server Routine ends ----------------------------------
  }
  else {
  // ------------------------ Client Routine begins ----------------------------------
    routine_begin(pipefd);
    int child_pid = fork();
    if (child_pid > 0){
    // ------------------------ Client TCP begins ----------------------------------
      // we are in father process
        // close the read pipe fd, cause the father does not need the child's feedback (lol)
      close(pipefd[0]);

      if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("socket()");
        exit(1);
      }
      // Client is easy, just need to connect to the only server.
      net_fd = client_connect_2_server(
        sock_fd,
        &remote,
        remote_ip,
        port
      );

      // exchange key
      client_in_key_exchange(net_fd, buffer);
      // send to the UDP process
      printf("ClientTCP: Sets the key/iv = %lx/%lx OK\n", *((long int *)key), *((long int *)iv));
      cwrite(pipefd[1], (char *)key, 32);
      cwrite(pipefd[1], (char *)iv, 32);
        // ServerTCP will tell this ClientTCP the exact port number of UDP connection
      My_SSL_read((char *)&port4udp, 2);
        // ClientTCP will tell this ServerTCP the exact virtual ip address of itself
      My_SSL_write((char *)&virtual_ip_number, 4);
        // Then tell the ClientUDP the port_number
      cwrite(pipefd[1], (char *)&port4udp, 2);
        // tell the ServerUDP the virtual ip address
      cwrite(pipefd[1], (char *)&virtual_ip_number, 4);

      // Client Key-IV Alter
      int Type_opt;
      while(scanf("%d", &Type_opt) == 1){
        if (Type_opt == 0){
          // change key
          RAND_bytes((char *)key, 32);
        }
        else{
          // change iv
          RAND_bytes((char *)iv, 32);
        }
        cwrite(pipefd[1], (char *)key, 32);
        cwrite(pipefd[1], (char *)iv, 32);
        if(My_SSL_write((char *)key, 32) <= 0){
          // Server is down
          break;
        }
        My_SSL_write((char *)iv, 32);
        printf("ClientTCP: RE-Sets the key/iv = %lx/%lx OK\n", *((long int *)key), *((long int *)iv));
      }

    // ------------------------ Client TCP ends ----------------------------------
      TCP_end(child_pid, pipefd);
    }
  // ------------------------ Client Routine ends ----------------------------------
  }
  
  /*
   UDP part, Client and Server sides are similar..
  */
  // we are in child process
    // close the write pipe fd, cause the child has no right to talk to father (lol)
  close(pipefd[1]);
  // read the key and iv from the TCP process
  cread(pipefd[0], (char *)key, 32);
  cread(pipefd[0], (char *)iv, 32);
  /*
    Here to init the encryption
  */
  init_AES();
  char *device_name = (cliserv == SERVER ? "Server" : "Client");
  printf("%sUDP: Sets the key/iv = %lx/%lx OK\n", device_name, *((long int *)key), *((long int *)iv));
    // recv port4udp from the TCP parent process
  cread(pipefd[0], (char *)&port4udp, 2);
    // recv virtual_ip_number from the TCP parent process
  cread(pipefd[0], (char *)&virtual_ip_number, 4);
  printf("%sUDP: use port number %d\n", device_name, port4udp);
  
  /*
    Register for the virtual tap
  */
    // now use virtual_ip_number to send a register to the server's guard process
  mqd_t mq_register = mq_open("/register", O_WRONLY);
  if (cliserv == SERVER){
    //... ServerUDP subprocess does the register
    mq_send(mq_register, (char *)&virtual_ip_number, 4, 1);
    printf("ServerUDP prcess which serves IP (%d.%d.%d.%d) sends a register application to the GUARD process!\n", 
            (virtual_ip_number >> 0) & 255, 
            (virtual_ip_number >> 8) & 255, 
            (virtual_ip_number >> 16) & 255, 
            (virtual_ip_number >> 24) & 255
          );
  }
  
  if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
    perror("socket()");
    exit(1);
  }
  set_sockaddr(&local, htonl(INADDR_ANY), htons(port4udp));

  if (cliserv == CLIENT){
    set_sockaddr(&remote, inet_addr(remote_ip), htons(port4udp));
  }
  else{
    // cread(pipefd[0], (char *)&remote, sizeof(remote));
    // recover the original port for the UDP usage, because it's already modified by the TCP / TCP&UDP don't use same port
    remote.sin_port = htons(port4udp);
  }


  net_fd = sock_fd;
  if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
    perror("setsockopt()");
    exit(1);
  }
  if (bind(sock_fd, (struct sockaddr*)&local, sizeof(local)) < 0){
    perror("bind()");
    exit(1);
  }
  
  /*
    Here we use the msg_queue from the guard process to simulate the virtual tap_fd
  */
  mqd_t fake_tap;
  if (cliserv == SERVER){
    char tmp[27] = "/server_";
    sprintf(tmp + 8, "%d", virtual_ip_number);
    fake_tap = mq_open(tmp, O_RDONLY);
  }
  
  /* use select() to handle two descriptors at once */
  if (cliserv == CLIENT)
    maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;
  else
    maxfd = (fake_tap > net_fd) ? fake_tap : net_fd;
  maxfd = (pipefd[0] > maxfd) ? pipefd[0] : maxfd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    if (cliserv == CLIENT)
      FD_SET(tap_fd, &rd_set); 
    else 
      FD_SET(fake_tap, &rd_set);
    FD_SET(net_fd, &rd_set);
    FD_SET(pipefd[0], &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0){
      perror("select()");
      exit(1);
    }

    if ((cliserv == CLIENT && FD_ISSET(tap_fd, &rd_set)) || (cliserv == SERVER && FD_ISSET(fake_tap, &rd_set))){
      /* data from tun/tap:
          first read it,
          then encrypt it, together with hashing-append,
          finally write it into the network
      */
      
      // read
      if (cliserv == CLIENT)
        nread = cread(tap_fd, buffer, BUFSIZE);
      else{
        nread = mq_receive(fake_tap, buffer, BUFSIZE * 5, NULL);
      }
      tap2net++;
      if (cliserv == CLIENT)  
        do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
      else 
        do_debug("Server MSQ2NET %lu: Read %d bytes from msg_queue\n", tap2net, nread);

      // encrypt & hash_append
      aes_encrypt(buffer, &nread);
        // nread at most increases 32 here
      append_HASH(buffer, &nread);

      // write into network
      plength = htons(nread);
      nwrite = cwrite_udp(net_fd, (char *)&plength, sizeof(plength), &remote, &remotelen);
      nwrite = cwrite_udp(net_fd, buffer, nread, &remote, &remotelen);
      if (cliserv == CLIENT)
        do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
      else
        do_debug("Server MSQ2NET %lu: Write %d bytes to the network\n", tap2net, nwrite);
    }

    if (FD_ISSET(net_fd, &rd_set)){
      /* data from the network: (won't be multiplex in a wrong way, the different port number ensures this.)
        first read it
        then check whether the hash is right, together with decrypting,
        finally write it into tun/tap
      */

      int whether_loss_pkg = 0;

      /* Read length */      
      nread = read_n_udp(net_fd, (char *)&plength, sizeof(plength), &remote, &remotelen);
      if (nread == 0) {
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

      // printf("%x %x %x %x %x\n", *((int *)(buffer + 0)), *((int *)(buffer + 4)), *((int *)(buffer + 8)), *((int *)(buffer + 12)), *((int *)(buffer + 16)));

      if (whether_loss_pkg == 0){
        /* write into tun/tap */ 
        nwrite = cwrite(tap_fd, buffer, nread);
        do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
      }
      else{
        printf("NET2TAP %lu: %d bytes from network are thrown away...\n", net2tap, nwrite);
      }
    }

    if (FD_ISSET(pipefd[0], &rd_set)){
      // we should change the key/iv pair
      cread(pipefd[0], (char *)key, 32);
      cread(pipefd[0], (char *)iv, 32);
        // re-init the encryption process
      init_AES();
      printf("%sUDP: RE-Sets the key/iv = %lx/%lx OK\n", device_name, *((long int *)key), *((long int *)iv));
    }
  }
  
  close(pipefd[0]); // close all the pipe file descriptors
  end_AES();
  return(0);
}
