#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

typedef struct ip ip_hdr;
typedef struct udphdr udp_hdr;

typedef struct {
  u_int32_t saddr;
  u_int32_t daddr;
  u_int8_t  filler;
  u_int8_t  protocol;
  u_int16_t len;
}ps_hdr;

typedef struct {
  unsigned short dns_id; // identification number

  unsigned char dns_rd :1; // recursion desired
  unsigned char dns_tc :1; // truncated message
  unsigned char dns_aa :1; // authoritive answer
  unsigned char dns_opcode :4; // purpose of message
  unsigned char dns_qr :1; // query/response flag

  unsigned char dns_rcode :4; // response code
  unsigned char dns_cd :1; // checking disabled
  unsigned char dns_ad :1; // authenticated data
  unsigned char dns_z  :1; // its z! reserved
  unsigned char dns_ra :1; // recursion available

  unsigned short dns_q_count; // number of question entries
  unsigned short dns_ans_count; // number of answer entries
  unsigned short dns_auth_count; // number of authority entries
  unsigned short dns_add_count; // number of resource entries
}dns_hdr;

typedef struct {
  unsigned short q_type;
  unsigned short q_class;
}query;

typedef struct {
  u_int16_t edns_type; // option
  u_int16_t edns_class; // sender's UDP payload size
  u_int32_t edns_ttl; // extended RCODE and flags
  u_int16_t edns_rdlen;
  unsigned short edns_opcode;
  unsigned short edns_oplen;
  unsigned short edns_opdata;
}edns_hdr;
