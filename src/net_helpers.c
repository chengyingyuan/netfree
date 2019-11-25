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
#include <stdarg.h>
#include <openssl/hmac.h>
#include "net_helpers.h"

int debug = 0;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
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

  if((nread=read(fd, buf, n)) < 0){
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

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
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
  
  if(debug) {
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

char* buffer_fill(char* buf, size_t len) {
  const char* scope = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_";
  const size_t scope_len = strlen(scope);
  for (size_t i=0; i<len; i++) {
    int idx = rand() % scope_len;
    buf[i] = scope[idx];
  }
  return buf;
}

ssize_t buffer_hmac(const char* key, const char* buf, size_t blen, char* hmac, size_t hlen) {
  const size_t hmac_len = HMAC_HASH_SIZE*2;
  const char* hexes = "0123456789abcdef";
  if (!hmac) {
    hlen  = hmac_len+1;
    hmac = (char*)malloc(hlen);
    hmac[hlen-1] = '\0';
  }
  if (hlen < hmac_len) {
    my_err("Hmac hash size %d too small\n", hlen);
    return -1;
  }

  // Length of digest depends on hash engine: EVP_sha1,EVP_224,EVP_sha512,EVP_md5
  // Link with -lcrypto
  unsigned char* digest = HMAC(EVP_sha1(), key, strlen(key), (const unsigned char*)buf, blen, NULL, NULL);
  for (int i=0; i<HMAC_HASH_SIZE; i++) {
    unsigned char c = digest[i];
    hmac[i*2] = hexes[((c&0xf0)>>4)];
    hmac[i*2+1] = hexes[(c&0x0f)];
    //sprintf(&hmac[i*2], "%02x", (unsigned int)digest[i]); // Add tailing '\0'
  }
  return hmac_len;
}

ssize_t buffer_xor(const char* key, size_t klen, char *buf, size_t blen) {
  for (size_t i=0; i<blen; i++) {
    buf[i] = buf[i] ^ key[i % klen];
  }
  return blen;
}

session_t* init_session(const char* username, const char* password, 
  unsigned short int port, const char* remoteip)  {
  session_t* sess = (session_t*)calloc(1, sizeof(session_t));
  sess->fd = -1;
  sess->raddr_len = sizeof(sess->raddr);
  memset(&sess->raddr, 0, sess->raddr_len);
  if (remoteip) {
    sess->raddr.sin_family = AF_INET;
    sess->raddr.sin_port = htons(port);
    if (inet_aton(remoteip, &sess->raddr.sin_addr)==0)  {
      perror("inet_aton()");
      goto err;
    }
    sess->remoteip = strdup(remoteip);
  }

  if ((sess->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket()");
    goto err;
  }
  /* avoid EADDRINUSE error on bind() */
  int optval = 1;
  if(setsockopt(sess->fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    goto err;
  }
  struct sockaddr_in local;
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(port);
  if (bind(sess->fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
    perror("bind()");
    goto err;
  }

  buffer_fill(sess->key, SESSION_KEYSIZE);
  sess->key[SESSION_KEYSIZE] = '\0';
  sess->username = strdup(username);
  sess->password = strdup(password);
  return sess;
err:
  destroy_session(sess);
  return NULL;
}

void destroy_session(session_t* sess) {
  if (sess->username) free(sess->username);
  if (sess->password) free(sess->password);
  if (sess->fd>=0) close(sess->fd);
  if (sess->endpoint) free(sess->endpoint);
  if (sess->remoteip) free(sess->remoteip);
  free(sess);
}

void reset_session(session_t* sess) {
  if (sess->endpoint) { free(sess->endpoint); sess->endpoint = NULL; }
  sess->last_ts = 0;
  if (!sess->remoteip) { // server side
    memset(&sess->raddr, 0, sess->raddr_len);
    memset(&sess->key, 0, sizeof(sess->key));
  } else {
    buffer_fill(sess->key, SESSION_KEYSIZE);
  }
}

// $SYN$<user>$<hmac>$<session-key>
ssize_t pack_sync(session_t* sess, char* buf, size_t blen) {
  size_t off  = pack_flag(buf, "SYN");
  *(buf+off) = '$'; off++;
  strcpy(buf+off, sess->username); 
  off += strlen(sess->username);
  *(buf+off) = '$'; off++;
  off += buffer_hmac(sess->password, sess->key, SESSION_KEYSIZE, buf+off, blen-off); 
  *(buf+off) = '$'; off++;
  strncpy(buf+off, sess->key, SESSION_KEYSIZE);
  off += buffer_xor(sess->password, strlen(sess->password), buf+off, SESSION_KEYSIZE);
  return off;
}

// $SYN$<user>$<hmac>$<session-key>
ssize_t unpack_sync(session_t* sess, char* buf, size_t blen) {
  size_t off = PACK_FLAG_LEN; 
  if (off+1>=blen) return -1;
  if (buf[off++] != '$') return -1;
  const char* username = buf+off; 
  while (off<blen && *(buf+off)!='$') off++;
  buf[off++] = '\0';
  if (strcmp(sess->username, username) != 0) return -1;
  
  const char* hmac = buf+off;
  while (off<blen && *(buf+off)!='$') off++;
  if (off>=blen) return -1;
  buf[off++] = '\0';
  
  size_t klen = blen - off;
  if (klen != SESSION_KEYSIZE) return -1;
  char* key = buf+off;
  buffer_xor(sess->password, strlen(sess->password), key, klen);
  
  char myhmac[HMAC_DIGEST_SIZE+1];
  buffer_hmac(sess->password, key, klen, myhmac, HMAC_DIGEST_SIZE);
  myhmac[HMAC_DIGEST_SIZE] = '\0';
  if(strcmp(myhmac, hmac) != 0) return -1;

  strncpy(sess->key, key, SESSION_KEYSIZE);
  sess->key[SESSION_KEYSIZE] = '\0';
  return 0;
}

// $SYA$<hmac>$<endpoint>
ssize_t pack_sync_ack(session_t* sess, char* buf, size_t blen) {
  size_t off  = pack_flag(buf, "SYA");
  *(buf+off) = '$'; off++;
  char* hmacbuf = buf+off;
  off += HMAC_DIGEST_SIZE;
  *(buf+off) = '$'; off++;
  char* epbuf = buf+off;
  char *ipaddr = inet_ntoa(sess->raddr.sin_addr);
  int port = ntohs(sess->raddr.sin_port);
  off += sprintf(epbuf, "%s:%d", ipaddr, port); // xxx.xxx.xxx.xxx:65536
  buffer_hmac(sess->key, epbuf, off-(epbuf-buf), hmacbuf, HMAC_DIGEST_SIZE); 
  buffer_xor(sess->key, SESSION_KEYSIZE, epbuf, off-(buf-epbuf));
  return off;
}

// $SYA$<hmac>$<endpoint>
ssize_t unpack_sync_ack(session_t* sess, char* buf, size_t blen)  {
  size_t off = PACK_FLAG_LEN; 
  if (off+1>=blen) return -1;
  if (buf[off++] != '$') return -1;
  const char* hmac = buf+off;
  while (off<blen && *(buf+off)!='$') off++;
  if (off>=blen || (off-(hmac-buf))!=HMAC_DIGEST_SIZE) return -1;
  buf[off++] = '\0';

  if (blen <= off) return -1;  
  size_t ep_len = blen - off;
  char* ep = buf+off;
  buffer_xor(sess->key, SESSION_KEYSIZE, ep, ep_len);

  char myhmac[HMAC_DIGEST_SIZE+1];
  buffer_hmac(sess->key, ep, ep_len, myhmac, HMAC_DIGEST_SIZE);
  myhmac[HMAC_DIGEST_SIZE] = '\0';
  if(strcmp(myhmac, hmac) != 0) return -1;

  sess->endpoint = strndup(ep, ep_len);
  return 0;
}

// $ACK$<hmac>$<endpoint>
ssize_t pack_ack(session_t* sess, char* buf, size_t blen) {
  ssize_t ret = pack_sync_ack(sess, buf, blen);
  if (ret>0) pack_flag(buf, "ACK");
  return ret;
}

// $ACK$<hmac>$<endpoint>
ssize_t unpack_ack(session_t* sess, char* buf, size_t blen) {
  return unpack_sync_ack(sess, buf, blen);
}

// $RST FIXME: Vulnerable to fake package attack
ssize_t pack_reset(session_t* sess,  char* buf, size_t blen) {
  return pack_flag(buf, "RST");
}

// $DAT<payload>
ssize_t pack_data(session_t* sess, char* buf, size_t blen, size_t dat_len) {
  size_t off = pack_flag(buf, "DAT");
  off += buffer_xor(sess->key, SESSION_KEYSIZE, buf+off, dat_len);
  return off;
}

// $DAT<payload>
ssize_t unpack_data(session_t* sess, char* buf, size_t blen) {
  size_t off = PACK_FLAG_LEN;
  off += buffer_xor(sess->key, SESSION_KEYSIZE, buf+off, blen-off);
  return off;
}
