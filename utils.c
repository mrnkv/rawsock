#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>


#include "utils.h"

const struct option long_options[] = {
  {"hight_end", required_argument, NULL, 'h'},
  {"low_end", required_argument, NULL , 'l'},
  {"h_speed", required_argument, NULL, 'H'},
  {"l_speed", required_argument, NULL, 'L'},
  {"cpu_freq", required_argument, NULL, 'f'},
  {"help", no_argument, NULL, 0}, 
  {NULL,0,NULL,0}
};

const char *short_options = "l:h:H:L:f:";

void display_usage(){
  printf("usage:\n");
  printf("bridge [-h|--high_end \"ifname\"] [-l|--low_end \"ifname\"] [-H|--h_speed N] [-L|--l_speed N] [--help]\n");
  printf("defaults:\n");
  printf("\t-h\teth0\n");
  printf("\t-l\teth1\n");
  printf("\t-H\t10\n");
  printf("\t-L\t2\n");
  printf("N -- speed in Mbit\n");
  printf("\t-f\t2000\n");
  printf("G -- CPU freq in MHz\n");
  printf("--help\t show this text\n");
}

void parse_args(int argc, char **argv, struct prog_args_t *args){
  /*set defaults*/
  strncpy(args->high_end_if, "eth0", IFNAMSIZ);
  strncpy(args->low_end_if, "eth1", IFNAMSIZ);
  args->high_speed = 10;
  args->low_speed = 2;
  args->cpu_freq = 2000;

  int opt = 0;
  int index = 0;
  opt = getopt_long( argc, argv, short_options, long_options, &index);
  while( opt != -1 ) {
    switch( opt ) {
      case 'h':{
        bzero(args->high_end_if, IFNAMSIZ);
        strncpy(args->high_end_if, optarg, IFNAMSIZ - 1); 
      }break;
      case 'l':{
        bzero(args->low_end_if, IFNAMSIZ);
        strncpy(args->low_end_if, optarg, IFNAMSIZ - 1); 
      }break;
      case 'L':{
        args->low_speed = strtol(optarg, NULL, 10);
        if(errno == ERANGE){
          printf ("bad L argument\n");
          display_usage();
          exit(EXIT_FAILURE);
        }
      }break;
      case 'H':{
        args->high_speed = strtol(optarg, NULL, 10);
        if(errno == ERANGE){
          printf ("bad H argument\n");
          display_usage();
          exit(EXIT_FAILURE);
        }
      }break;
      case 'f':{
        args->cpu_freq = strtol(optarg, NULL, 10);
        if(errno == ERANGE){
          printf ("bad cpu_freq  argument\n");
          display_usage();
          exit(EXIT_FAILURE);
        }
      }break;
      case 0:{
        if(strcmp( "help", long_options[index].name) == 0 ){
          display_usage();
        }
      }break;
      default:
      break;
    }
    opt = getopt_long( argc, argv, short_options, long_options, &index);
  }
  if(args->low_speed > args->high_speed){
    printf("Low speed must be lower then high speed\n");
    display_usage();
    exit(EXIT_FAILURE);
  }
}

int get_sock_fd(char *if_name){
  int sockfd;
  int sockopt;
  struct packet_mreq mreq = {0};
  struct sockaddr_ll addr = {0};
  struct ifreq ifopts = {0};
  if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1){
    perror("open socket");
    return (-1);
  }
  strncpy(ifopts.ifr_name, if_name, IFNAMSIZ-1);
  if(ioctl(sockfd, SIOCGIFINDEX, &ifopts) < 0){
    perror("ifindex");
    return (-2);
  }else{
    printf("Interface index: %d\n",  ifopts.ifr_ifindex); 
  }
  addr.sll_family = AF_PACKET;
  addr.sll_ifindex = ifopts.ifr_ifindex;
  addr.sll_protocol = htons(ETH_P_ALL);
  if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1){
    perror("bind");
    return (-3);
  }

  mreq.mr_ifindex = ifopts.ifr_ifindex;
  mreq.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
    perror("setsockopt promisc");
    return (-4);
  }
  return sockfd;
}

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

void set_flow_ctrl_delay(uint8_t *pkt, uint16_t delay){
  uint16_t *pause_time = (void*)pkt + sizeof(struct ether_header) + 2;
  *pause_time = htons(delay);
}

uint64_t rdtsc(){
  unsigned int lo,hi;
  __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
  return ((uint64_t)hi << 32) | lo;
}

