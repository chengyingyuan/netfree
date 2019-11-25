#ifndef NET_HELPERS_H
#define NET_HELPERS_H

#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>

#define HMAC_HASH_SIZE 20
#define HMAC_DIGEST_SIZE 40
#define SESSION_KEYSIZE 32
#define PACK_FLAG_LEN 4  // $SYN, $SYA, $ACK, $DAT, $RST

extern int debug;

typedef struct session {
  char* username;
  char* password;
  char key[SESSION_KEYSIZE+1];
  int fd;
  struct sockaddr_in raddr;
  socklen_t raddr_len;
  char*  remoteip;
  char* endpoint; // ip:port
  time_t last_ts; // last time of activity

} session_t;

int tun_alloc(char *dev, int flags);
int cread(int fd, char *buf, int n);
int cwrite(int fd, char *buf, int n);
int read_n(int fd, char *buf, int n);
void do_debug(char *msg, ...);
void my_err(char *msg, ...);

session_t* init_session(const char* username, const char* password, 
  unsigned short int port, const char* remote_ip);
void destroy_session(session_t* sess);
char* buffer_fill(char* buf, size_t len);
ssize_t buffer_hmac(const char* key, const char* buf, size_t blen, char* hmac, size_t hlen);
ssize_t buffer_xor(const char* key, size_t klen, char *buf, size_t blen);

static inline int is_sync(char* buf, size_t blen) {
  return (blen>4 && buf[0]=='$' && buf[1]=='S' && buf[2]=='Y' && buf[3]=='N');
}
static inline int is_sync_ack(char* buf, size_t blen) {
  return (blen>4 && buf[0]=='$' && buf[1]=='S' && buf[2]=='Y' && buf[3]=='A');
}
static inline int is_ack(char* buf, size_t blen) {
  return (blen>4 && buf[0]=='$' && buf[1]=='A' && buf[2]=='C' && buf[3]=='K');
}
static inline int is_reset(char* buf, size_t blen) {
  return (blen>=4 && buf[0]=='$' && buf[1]=='R' && buf[2]=='S' && buf[3]=='T');
}
static inline int is_data(char* buf, size_t blen) {
  return (blen>4 && buf[0]=='$' && buf[1]=='D' && buf[2]=='A' && buf[3]=='T');
}
static inline size_t pack_flag(char* buf, char* flag) {
  buf[0] = '$'; buf[1] = flag[0]; buf[2] = flag[1]; buf[3] = flag[2];
  return PACK_FLAG_LEN;
}

ssize_t pack_sync(session_t* sess, char* buf, size_t blen);
ssize_t unpack_sync(session_t* sess, char* buf, size_t blen);
ssize_t pack_sync_ack(session_t* sess, char* buf, size_t blen);
ssize_t unpack_sync_ack(session_t* sess, char* buf, size_t blen);
ssize_t pack_ack(session_t* sess, char* buf, size_t blen);
ssize_t unpack_ack(session_t* sess, char* buf, size_t blen);
ssize_t pack_reset(session_t* sess,  char* buf, size_t blen);
ssize_t pack_data(session_t* sess, char* buf, size_t blen, size_t dat_len);
ssize_t unpack_data(session_t* sess, char* buf, size_t blen);

#endif
