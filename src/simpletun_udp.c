#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <openssl/hmac.h>
#include "net_helpers.h"

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define PORT 55555
#define ENV_USERNAME "NETFREE_USERNAME"
#define ENV_PASSWORD "NETFREE_PASSWORD"
#define SESSION_DIFF_TIMEOUT 10

char *progname;
char buffer[BUFSIZE];
ssize_t blen = 0;


static inline int reply_reset(session_t* sess, struct sockaddr_in* raddr, socklen_t raddr_len) {
  ssize_t blen = pack_reset(sess, buffer, BUFSIZE);
  ssize_t ret = sendto(sess->fd, buffer, blen, 0, (struct sockaddr *)raddr, raddr_len);
  if (ret < 0) {
    perror("reply reset sendto()");
    return -1;
  }
  return 0;
}

static inline int reply_ack(session_t* sess) {
  blen = pack_ack(sess, buffer, BUFSIZE);
  ssize_t ret = sendto(sess->fd, buffer, blen, 0, (struct sockaddr *)&sess->raddr, sess->raddr_len);
  if (ret < 0) {
    perror("client sync sendto()");
    return -1;
  }
  return 0;
}

int client_negotiate(session_t* sess) {
  struct sockaddr_in  raddr;
  socklen_t raddr_len = sizeof(raddr);
  struct timeval timeout;
  fd_set rd_set;
  ssize_t ret;

  int ntries = 0;
  while(1) {
    blen = pack_sync(sess, buffer, BUFSIZE);
    ret = sendto(sess->fd, buffer, blen, 0, (struct sockaddr *)&sess->raddr, sess->raddr_len);
    if (ret < 0) {
      perror("client sync sendto()");
      return -1;
    }
    do_debug("client sync sent.\n");

    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    FD_ZERO(&rd_set);
    FD_SET(sess->fd, &rd_set);
    ret = select(sess->fd+1, &rd_set, NULL, NULL, &timeout);
    if (ret < 0) {
      perror("client sync select()");
      return -1;
    }
    if(FD_ISSET(sess->fd, &rd_set)) {
      blen = recvfrom(sess->fd, buffer, BUFSIZE, 0, (struct sockaddr*)&raddr, &raddr_len);
      if (blen < 0) {
        perror("client sync recvfrom()");
        return -1;
      }
      if (is_sync_ack(buffer, blen)) {
        ret = unpack_sync_ack(sess, buffer, blen);
        if (ret < 0) {
          my_err("client ill-sync_ack pack.\n");
        } else { // Sync success
          do_debug("client sync_ack received.\n");
          break;
        }
      }
    }
    ntries++;
    do_debug("client sync tried %d time(s)\n", ntries);
  }

  if (reply_ack(sess) < 0) return -1;
  do_debug("client ack sent.\n");
  sess->last_ts = time(NULL);
  do_debug("client session ready.\n");
  return 0;
}

ssize_t server_negotiate(session_t* sess) {
  struct sockaddr_in  raddr;
  socklen_t raddr_len = sizeof(raddr);
  struct timeval timeout;
  fd_set rd_set;
  ssize_t ret;
  int done = 0;

  while(!done) {
    // Wait sync
    int ntries = 0;
    while(1) {
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      FD_ZERO(&rd_set);
      FD_SET(sess->fd, &rd_set);
      ret = select(sess->fd+1, &rd_set, NULL, NULL, &timeout);
      if (ret < 0) {
        perror("server sync select()");
        return -1;
      }
      if(FD_ISSET(sess->fd, &rd_set)) {
        memset(&raddr, 0, raddr_len);
        blen = recvfrom(sess->fd, buffer, BUFSIZE, 0, (struct sockaddr*)&raddr, &raddr_len);
        if (blen < 0) {
          perror("server sync recvfrom()");
          return -1;
        }
        if (!is_sync(buffer, blen)) { // Reply with reset if not sync
          my_err("server receive non-sync data.\n");
          if (reply_reset(sess, &raddr, raddr_len)!=0) return -1;
        } else {
          ret = unpack_sync(sess, buffer, blen);
          if (ret < 0) { // Maybe password is wrong
            my_err("server receive ill-sync data.\n");
            if (reply_reset(sess, &raddr, raddr_len)!=0) return -1;
          } else { // Lock to this client
            do_debug("server sync received.\n");
            memcpy(&sess->raddr, &raddr, raddr_len);
            sess->raddr_len = raddr_len;
            break;
          }
        }
      }
      ntries++;
      do_debug("server sync tried %d time(s)\n", ntries);
    }

    // Wait ack
    ntries  = 0;
    while (1) {
      blen = pack_sync_ack(sess, buffer, BUFSIZE);
      ret = sendto(sess->fd, buffer, blen, 0, (struct sockaddr *)&sess->raddr, sess->raddr_len);
      if (ret < 0) {
        perror("server sync_ack sendto()");
        return -1;
      }
      do_debug("server sync_ack sent\n");

      timeout.tv_sec = 2;
      timeout.tv_usec = 0;
      FD_ZERO(&rd_set);
      FD_SET(sess->fd, &rd_set);
      ret = select(sess->fd+1, &rd_set, NULL, NULL, &timeout);
      if (ret < 0) {
        perror("server ack select()");
        return -1;
      }
      if(FD_ISSET(sess->fd, &rd_set)) {
        blen = recvfrom(sess->fd, buffer, BUFSIZE, 0, (struct sockaddr*)&raddr, &raddr_len);
        if (blen < 0) {
          perror("server ack recvfrom()");
          return -1;
        }
        if (memcmp(&sess->raddr, &raddr, raddr_len) != 0) { // Different client
          my_err("server ack client diff.\n");
          if (reply_reset(sess, &raddr, raddr_len)!=0) return -1;
        } else if (is_ack(buffer, blen)) {
          ret = unpack_ack(sess, buffer, blen);
          if (ret < 0) {
            my_err("server failed unpack_ack()\n");
             if (reply_reset(sess, &raddr, raddr_len)!=0) return -1;
            break; // restart sync
          } else {
            do_debug("server ack received.\n");
            done = 1;
            break;
          }
        } else if (is_data(buffer, blen)) { // Data also indicates ack
          do_debug("server acked by data.\n");
          done = 1;
          break;
        }
      }
      ntries++;
      if (ntries >= 3) { // waiting ntries*2 seconds
        my_err("server ack timed out.\n");
        break; // restart sync
      }
      do_debug("server ack tried %d time(s)\n", ntries);
    }
  }

  sess->last_ts = time(NULL);
  do_debug("server session ready.\n");
  return blen;
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-r <remoteIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-r <remoteIP>: Remote ip address to send to\n");
  fprintf(stderr, "-p <port>: port to listen on and to connect to if remote ip specified, default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

ssize_t do_client(session_t* sess, int tap_fd) {
  struct sockaddr_in raddr;
  socklen_t raddr_len = sizeof(raddr);
  unsigned long int tap2net = 0;
  unsigned long int net2tap = 0;
  int nread, nwrite;
  fd_set rd_set;

  ssize_t ret = client_negotiate(sess);
  if (ret < 0) return ret;

  int maxfd = (tap_fd > sess->fd)?tap_fd:sess->fd;
  while(1) {
    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); 
    FD_SET(sess->fd, &rd_set);
    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
    if (ret < 0) {
      perror("client select()");
      if (errno!=EINTR) return -1;
      continue;
    }

    if(FD_ISSET(tap_fd, &rd_set)) {
      /* data from tun/tap: just read it and write it to the network */
      nread = cread(tap_fd, buffer+PACK_FLAG_LEN, BUFSIZE-PACK_FLAG_LEN);
      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
      blen = pack_data(sess, buffer, BUFSIZE, nread);
      ret  = sendto(sess->fd, buffer, blen, 0, (struct sockaddr *)&sess->raddr, sess->raddr_len);
      if (ret < 0) {
        perror("client sendto()");
        if (errno!=EINTR) return -1;
        // FIXME: Retry interrupted pack
      } else {
        do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
      }
    }

    if(FD_ISSET(sess->fd, &rd_set)) {
      /* data from the network: read it, and write it to the tun/tap interface. */
      ret = recvfrom(sess->fd, buffer, BUFSIZE, 0, (struct sockaddr*)&raddr, &raddr_len);
      if (ret < 0) {
        perror("client recvfrom()");
        if (errno!=EINTR) return -1;
        continue;
      }
      net2tap++;
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, ret);
      if (memcmp(&sess->raddr, &raddr, raddr_len)!=0) { // A different server
        my_err("received from diff server.\n");
        if (reply_reset(sess, &raddr, raddr_len)<0) return -1;
        continue;
      }
      if(ret == 0) {
        /* ctrl-c at the other end */
        do_debug("server eof.\n");
        break;
      }
      sess->last_ts = time(NULL);
      if (is_sync_ack(buffer, ret)) { // server is waiting ack, ack maybe lost
        if (reply_ack(sess) < 0) return -1;
        do_debug("client resend ack.\n");
        continue;
      }
      if (is_reset(buffer, ret)) {
        do_debug("client resync necessary.\n");
        break;
      }
      assert(is_data(buffer, ret));
      blen = unpack_data(sess, buffer, ret);
      nwrite = cwrite(tap_fd, buffer+PACK_FLAG_LEN, blen-PACK_FLAG_LEN);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  
  return(0);
}

ssize_t do_server(session_t* sess, int tap_fd) {
  struct sockaddr_in raddr;
  socklen_t raddr_len = sizeof(raddr);
  unsigned long int tap2net = 0;
  unsigned long int net2tap = 0;
  int nread, nwrite;
  fd_set rd_set;

  ssize_t ret = server_negotiate(sess);
  if (ret < 0) return ret;

  if (is_data(buffer, ret)) { // client ack with data
    do_debug("client data with ack received.\n");
    net2tap++;
    nwrite = cwrite(tap_fd, buffer+PACK_FLAG_LEN, ret-PACK_FLAG_LEN);
    do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
  }

  int maxfd = (tap_fd > sess->fd)?tap_fd:sess->fd;
  while(1) {
    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); 
    FD_SET(sess->fd, &rd_set);
    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
    if (ret < 0) {
      perror("server select()");
      if (errno!=EINTR) return -1;
      continue;
    }

    if(FD_ISSET(tap_fd, &rd_set)) {
      /* data from tun/tap: just read it and write it to the network */
      nread = cread(tap_fd, buffer+PACK_FLAG_LEN, BUFSIZE);
      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
      blen = pack_data(sess, buffer, BUFSIZE, nread);
      ret  = sendto(sess->fd, buffer, blen, 0, (struct sockaddr *)&sess->raddr, sess->raddr_len);
      if (ret < 0) {
        perror("server sendto()");
        if (errno!=EINTR) return -1;
        // FIXME: Retry interrupted pack
      } else {
        do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, ret);
      }
    }

    if(FD_ISSET(sess->fd, &rd_set)) {
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */
      ret = recvfrom(sess->fd, buffer, BUFSIZE, 0, (struct sockaddr*)&raddr, &raddr_len);
      if (ret < 0) {
        perror("server recvfrom()");
        if (errno!=EINTR) return -1;
        continue;
      }
      net2tap++;
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, ret);
      if (memcmp(&sess->raddr, &raddr, raddr_len)!=0) { // a different client
        my_err("received from diff client.\n");
        time_t now = time(NULL);
        if (now-sess->last_ts > SESSION_DIFF_TIMEOUT) { // client restarted
          do_debug("restart server for client diff.\n");
          break;
        }
        //if (reply_reset(sess, &raddr, raddr_len)<0) return -1;
        continue; // wait until timed out
      }
      if(ret == 0) {
        /* ctrl-c at the other end */
        do_debug("client eof.\n");
        break;
      }
      sess->last_ts = time(NULL);
      if (is_ack(buffer, ret)) { // server is waiting ack, ack maybe lost
        do_debug("received duplicated ack.\n");
        continue;
      }
      if (!is_data(buffer, ret)) { // maybe client restarted
        do_debug("connection broken.\n");
        break;
      }

      unpack_data(sess, buffer, ret);
      nwrite = cwrite(tap_fd, buffer+PACK_FLAG_LEN, ret-PACK_FLAG_LEN);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  
  return(0);
}

int main(int argc, char *argv[]) {
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int port = PORT;
  char* remote_ip = NULL;
  session_t* sess = NULL;
  const char* username = NULL;
  const char* password = NULL;
  ssize_t ret = 0;

  username = getenv(ENV_USERNAME);
  password = getenv(ENV_PASSWORD);
  if (!username || !password) {
    my_err("Environment %s and %s should be set\n", ENV_USERNAME, ENV_PASSWORD);
    return -1;
  }

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:r:p:uahd")) > 0) {
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name, optarg, IFNAMSIZ-1);
        break;
      case 'r':
        remote_ip = strdup(optarg);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  sess = init_session(username, password, port, remote_ip);
  assert(sess);
  if (remote_ip) ret = do_client(sess, tap_fd);
  else ret = do_server(sess, tap_fd);
  close(tap_fd);
  destroy_session(sess);
  return ret; 
}
