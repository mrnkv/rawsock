#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <stdbool.h>


#define ETHER_TYPE ETHERTYPE_IP

#define BUF_SIZE    65537

struct progArgs_t {
  struct ether_addr dst_mac;
  struct ether_addr src_mac;
  char *if_name;
};

static const char *opt_string = "d:s:i:";

void display_usage(){
  printf("usage:\n");
  printf("recvraweth -i (interface) -s (source mac addr) -d (destination mac addr) \n");
  printf("defaults:\n");
  printf("\t-i\teth0\n");
  printf("\t-s\t00:00:00:00:00:00\n");
  printf("\t-d\t00:00:00:00:00:00\n");
  printf("in case -d or -s != \"zeros\" packets will be filtered by not zeros MACs");
}



int main(int argc, char *argv[]){
  char sender[INET6_ADDRSTRLEN];

  int sockfd, ret, i;
  int sockopt;
  size_t numbytes;

  struct ifreq ifopts = {0};
  struct ifreq if_idx = {0};
  struct ifreq if_ip = {0};

  int opt = 0;
 
  uint8_t buf[BUF_SIZE];

  struct packet_mreq mreq = {0};
  struct sockaddr_ll addr = {0};
  
  struct ether_header *eh = (struct ether_header*)buf;

  size_t *frame_number;
  
  struct progArgs_t prog_args;

  bool src_filter = true, dst_filter = true;
  
  //prepare default args
  prog_args.if_name = "eth0";
  bzero((void*)(&prog_args.dst_mac), ETH_ALEN);
  bzero((void*)(&prog_args.src_mac), ETH_ALEN);

  frame_number = (void*)(buf + ETH_HLEN);

  //read cli args
  opt = getopt(argc, argv, opt_string);
  while(opt != -1){
    switch(opt){
      case 'i': 
        prog_args.if_name = optarg;
        break;
      case 'd':
        if(ether_aton_r(optarg, &prog_args.dst_mac) == NULL){
          printf("Wrong destination mac addr format!\n");
          display_usage();
          exit(EXIT_FAILURE);
        }
        break;
      case 's':
        if(ether_aton_r(optarg, &prog_args.src_mac) == NULL){
          printf("Wrong source mac addr format!\n");
          display_usage();
          exit(EXIT_FAILURE);
        }
        break;
      case 'h':
      case '?':
        display_usage();
        exit(EXIT_FAILURE);
        break;
      default:
        break;
    }
    opt = getopt(argc, argv, opt_string);
  }

  //open socket
  if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1){
    perror("lsn socket");
    exit(EXIT_FAILURE);
  }

  //bind socket to interface
  strncpy(ifopts.ifr_name, prog_args.if_name, IFNAMSIZ-1);
  if(ioctl(sockfd, SIOCGIFINDEX, &ifopts) < 0){
    perror("ifindex");
    exit(EXIT_FAILURE);
  }else{
    printf("Interface index: %d\n",  ifopts.ifr_ifindex); 
  }
  addr.sll_family = AF_PACKET;
  addr.sll_ifindex = ifopts.ifr_ifindex;
  addr.sll_protocol = htons(ETH_P_ALL);
  if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  //set promisc mode
  mreq.mr_ifindex = ifopts.ifr_ifindex;
  mreq.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
    perror("setsockopt promisc");
    exit(EXIT_FAILURE);
  }

  //check filters
  if(prog_args.src_mac.ether_addr_octet[0] == 0
     && prog_args.src_mac.ether_addr_octet[1] == 0
     && prog_args.src_mac.ether_addr_octet[2] == 0
     && prog_args.src_mac.ether_addr_octet[3] == 0
     && prog_args.src_mac.ether_addr_octet[4] == 0)
    src_filter = false;
  if(prog_args.dst_mac.ether_addr_octet[0] == 0
     && prog_args.dst_mac.ether_addr_octet[1] == 0
     && prog_args.dst_mac.ether_addr_octet[2] == 0
     && prog_args.dst_mac.ether_addr_octet[3] == 0
     && prog_args.dst_mac.ether_addr_octet[4] == 0)
    dst_filter = false;
      
  if(src_filter && dst_filter){ //both filters
    printf("listener: Waiting to recvfrom... src: %s dst: %s\n", 
        ether_ntoa(&prog_args.src_mac), ether_ntoa(&prog_args.dst_mac));
  }
  if(!src_filter && !dst_filter){ //no filters
    printf("listener: Waiting to recvfrom... (all packets)\n");
  }
  if(src_filter && !dst_filter){ //src filter
    printf("listener: Waiting to recvfrom... src: %s\n", 
        ether_ntoa(&prog_args.src_mac));
  }
  if(!src_filter && dst_filter){ //dst filter
    printf("listener: Waiting to recvfrom... dst: %s\n", 
        ether_ntoa(&prog_args.dst_mac));
  }
  do{
    numbytes = recvfrom(sockfd, buf, BUF_SIZE, 0, NULL, NULL);
    printf("Packet number: %zu packet len: %zu\n", *frame_number, numbytes);
  }while(*frame_number > 1);
                      
  close(sockfd);
  return 0;
}
