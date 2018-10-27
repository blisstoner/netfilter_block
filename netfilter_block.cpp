#include <errno.h>
//#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <libnet.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define NF_DROP 0
#define NF_ACCEPT 1

char* block_url;
int block_url_size;
int packet_to_ip_hdr(const uint8_t *p, struct libnet_ipv4_hdr *ip_hdr) {
  ip_hdr->ip_v = (uint8_t)((*p) >> 4);
  ip_hdr->ip_hl = (uint8_t)((*(p++) & 0xf));
  ip_hdr->ip_tos = (uint8_t) * (p++);
  ip_hdr->ip_len = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  ip_hdr->ip_id = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  ip_hdr->ip_off = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  ip_hdr->ip_ttl = (uint8_t) * (p++);
  ip_hdr->ip_p = (uint8_t) * (p++);
  ip_hdr->ip_sum = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  ip_hdr->ip_src.s_addr = ntohl(*static_cast<uint32_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 4;
  ip_hdr->ip_dst.s_addr = ntohl(*static_cast<uint32_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 4;
  if (ip_hdr->ip_hl < 5) {
    printf("[!]wrong IHL value(%d) in IP header\n", ip_hdr->ip_hl);
    return -1;
  }
  if (ip_hdr->ip_hl > 5) {
    uint32_t option_len = (ip_hdr->ip_hl - 5) << 2;
    uint8_t ip_option[option_len];  // maybe it will use in someday..?
    for (int i = 0; i < option_len; i++) ip_option[i] = (uint8_t) * (p++);
  }
  return 0;
}

int packet_to_tcp_hdr(const uint8_t *p, struct libnet_tcp_hdr *tcp_hdr){
  tcp_hdr->th_sport = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_dport = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_seq = ntohs(*static_cast<uint32_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 4;
  tcp_hdr->th_ack = ntohs(*static_cast<uint32_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 4;

  tcp_hdr->th_off = (uint8_t)((*p) >> 4);
  tcp_hdr->th_x2 = (uint8_t)((*(p++)) & 0xf);
  tcp_hdr->th_flags = (uint8_t) * (p++);
  tcp_hdr->th_win = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_sum = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  tcp_hdr->th_urp = ntohs(*static_cast<uint16_t *>(
      static_cast<void *>((const_cast<uint8_t *>(p)))));
  p += 2;
  if(tcp_hdr->th_off < 5){
    printf("[!]wrong tcp offset(%d)\n", tcp_hdr->th_off);
    return -1;
  }
  uint32_t option_len = (tcp_hdr->th_off - 5) << 2;
  uint8_t tcp_option[option_len];
  for (int i = 0; i < option_len; i++) tcp_option[i] = (uint8_t) * (p++);
  return 0;
}

// true if url is same as block_url
int is_block_url(uint8_t* data, int len){
  if(len < 8) return 0;
  const char* http_method[6] = {"GET","POST","HEAD","PUT","DELETE","OPTIONS"};
  int http_method_size[6] = {3,4,4,3,6,7};
  int i = 0;
  while(i < 6){
    if(memcmp(data,http_method[i],http_method_size[i]) == 0) break;
    i++;
  }
  if(i == 6) return 0;
  for(int i = 0; i < len-block_url_size-6; i++){
    if(memcmp(data+i, "Host: ", 6) == 0){
      printf("url : ");
      uint8_t* c = data+i+6;
      while(*c != 0x0d){
        printf("%c", *c);
        c++;
      }
      printf("\n");
      if(memcmp(data+i+6,block_url, block_url_size) == 0) return 1;
    }    
  }
  return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                  struct nfq_data *nfa, void *data) {
  u_int32_t id = 0;
  struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
  if (ph)  id = ntohl(ph->packet_id);
  uint8_t* p;
  int32_t len = nfq_get_payload(nfa, &p);
  libnet_ipv4_hdr ip_hdr;
  libnet_tcp_hdr tcp_hdr;
  if(packet_to_ip_hdr(p,&ip_hdr) == 0){
    if(ip_hdr.ip_p == IPPROTO_TCP and \
    packet_to_tcp_hdr(p+(ip_hdr.ip_hl<<2), &tcp_hdr) == 0){
      uint8_t* tcp_data = p+(ip_hdr.ip_hl<<2)+(tcp_hdr.th_off<<2);
      int data_len = len - (ip_hdr.ip_hl << 2) - (tcp_hdr.th_off << 2);
      if(is_block_url(tcp_data,data_len)){
        printf("blocked ^o^\n");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
      }
    }
  }
  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void usage(){
  printf("syntax: netfilter_block <host>\n");
  printf("sample: netfilter_block test.gilgil.net\n");
}
int main(int argc, char **argv) {
  if(argc != 2){
    usage();
    return -1;
  }
  block_url = argv[1];
  block_url_size = strlen(block_url);
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096] __attribute__((aligned));

  printf("opening library handle\n");
  h = nfq_open();
  if (!h) {
    fprintf(stderr, "error during nfq_open()\n");
    exit(1);
  }

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    exit(1);
  }

  printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    exit(1);
  }

  printf("binding this socket to queue '0'\n");
  qh = nfq_create_queue(h, 0, &cb, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }

  fd = nfq_fd(h);
  for (;;) {
    if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
      nfq_handle_packet(h, buf, rv);
      continue;
    }
    /* if your application is too slow to digest the packets that
     * are sent from kernel-space, the socket buffer that we use
     * to enqueue packets may fill up returning ENOBUFS. Depending
     * on your application, this error may be ignored.
     * nfq_nlmsg_verdict_putPlease, see the doxygen documentation of this
     * library on how to improve this situation.
     */
    if (rv < 0 && errno == ENOBUFS) {
      printf("losing packets!\n");
      continue;
    }
    perror("recv failed");
    break;
  }

  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

#ifdef INSANE
  /* normally, applications SHOULD NOT issue this command, since
   * it detaches other programs/sockets from AF_INET, too ! */
  printf("unbinding from AF_INET\n");
  nfq_unbind_pf(h, AF_INET);
#endif

  printf("closing library handle\n");
  nfq_close(h);

  exit(0);
}
