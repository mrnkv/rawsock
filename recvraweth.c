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
#include <errno.h>
#include <pcap.h>

#define ETHER_TYPE ETHERTYPE_IP

#define BUF_SIZE    65537
#define DELAY_PKT_SIZE 60

struct progArgs_t {
  struct ether_addr dst_mac;
  struct ether_addr src_mac;
  char *if_name;
};

static const char *opt_string = "d:s:i:p:";

void display_usage(){
  printf("usage:\n");
  printf("recvraweth -i (interface) -s (source mac addr) -d (destination mac addr) -p (pause usec)\n");
  printf("defaults:\n");
  printf("\t-i\teth0\n");
  printf("\t-s\t00:00:00:00:00:00\n");
  printf("\t-d\t00:00:00:00:00:00\n");
  printf("\t-p\t0\n");
  printf("in case -d or -s != \"zeros\" packets will be filtered by not zeros MACs\n");
}
//===========GLOBAL VARS=============================
size_t global_pck_counter = 0;;
uint8_t delay_pkt[DELAY_PKT_SIZE];
pcap_t *adhandle; //for initializing device, whill hold the chosen one
//===================================================

void prepare_flow_control_pkt(uint8_t *pkt){
  struct ether_header *eh = (struct ether_header*)pkt;
  ether_aton_r("01:80:c2:00:00:01", (struct ether_addr*)eh->ether_dhost);
  ether_aton_r("00:00:00:00:00:00", (struct ether_addr*)eh->ether_shost);
  eh->ether_type = htons(ETH_P_PAUSE);
  uint16_t *mac_opcode = (void*)pkt + sizeof(struct ether_header);
  *mac_opcode = htons(0x0001);
  uint16_t *pause_time = (void*)pkt + sizeof(struct ether_header) + 2;
  *pause_time = htons(0xffff);
  bzero((void*)(pkt + sizeof(struct ether_header) + 4/*mac_opcode + pause_time*/), 42);
}
/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
  global_pck_counter++;
  printf("recieved %lu packts\n", global_pck_counter);
  pcap_inject(adhandle, delay_pkt, DELAY_PKT_SIZE);
}

int main(int argc, char *argv[]){
  char sender[INET6_ADDRSTRLEN];

  int sockfd, ret, i;
  int sockopt;
  size_t numbytes;
  size_t delay_usec = 0;

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
      case 'p':
        delay_usec = atoi(optarg);
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

  prepare_flow_control_pkt(delay_pkt);

  //====================pcap init===================
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs; //for initializing device, will hold all
  pcap_if_t *d; //for initializing device, iterator
  int inum; //for initializing device, iterator for printing, choosing
  struct bpf_program fcode;
  if(pcap_findalldevs(&alldevs, errbuf) == -1){
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }
  /* Print the list */
  i = 0;
  d = alldevs;
  bool target_dev = false;
  while(!target_dev && d != NULL){
    if (strcmp(prog_args.if_name, d->name) == 0){
      target_dev = true;
    }
    printf("%d. %s", ++i, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n");
    if(!target_dev) 
      d = d->next;
  }
  if(!d){
    printf("No such device\n");
    pcap_freealldevs(alldevs);/* Free the device list */
    exit(EXIT_FAILURE);
  }else{
    printf("selected device: %s\n", d->name);
  }

  /* Open the adapter */
  if ((adhandle= pcap_open_live(d->name, // name of the device
          65536, // portion of the packet to capture: 65536 grants that the whole packet will be captured on all the MACs.
          1,// promiscuous mode (nonzero means promiscuous)
          1000, // read timeout
          errbuf // error buffer
          )) == NULL){
    printf("\nUnable to open the adapter.\n");
    pcap_freealldevs(alldevs);
    return EXIT_FAILURE;
  }
  printf("\nlistening on %s...\n", d->description);
  pcap_freealldevs(alldevs);
  pcap_loop(adhandle, 0, packet_handler, NULL);
  //================================================
  return 0;
}
