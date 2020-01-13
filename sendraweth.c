#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>

#define BUF_SIZE    65535 

unsigned short checksum(unsigned short* buff, int _16bitword)
{
  unsigned long sum;
  for(sum=0;_16bitword>0;_16bitword--)
    sum+=htons(*(buff)++);
  sum = ((sum >> 16) + (sum & 0xFFFF));
  sum += (sum>>16);
  return (unsigned short)(~sum);
}

struct progArgs_t {
  size_t msg_size;
  size_t msg_count;
  char *if_name;
  char *dst_mac;
  uint8_t pattern;
  bool use_udp;
  useconds_t delay;
};

static const char *opt_string = "b:i:d:c:p:t:uh?";

void display_usage(){
  printf("sendraweth -b (msg size in bytes) -c (msg count) -i (interface) -s (source mac addr) -d (destination mac addr) -p (hex pattern of payload)\n");
  printf("defaults:\n");
  printf("\t-b\t256\n");
  printf("\t-c\t1\n");
  printf("\t-i\teth0\n");
  printf("\t-s\t00:00:00:00:00:00\n");
  printf("\t-t\t0\n");
  printf("\t-p\t01\n");
}



int main(int argc, char *argv[]){


  struct progArgs_t prog_args;
  int sockfd;
  struct ifreq if_idx = {0};
  struct ifreq if_mac = {0};
  int tx_len = 0;
  char sendbuf[BUF_SIZE] = {0};
  struct ether_header *eh = (struct ether_header*)sendbuf;
  struct iphdr *iph = (struct iphdr*)(sendbuf + sizeof(struct ether_header));
  struct udphdr *udph = (struct udphdr*)(sendbuf + sizeof(struct ether_header) + sizeof(struct iphdr));
  struct sockaddr_ll socket_address;
  int send_count;
  size_t *msg_count_ptr;
  size_t msg_count;
  size_t msg_count_fault;
  int opt = 0;
  int scanf_result;
  struct timespec start, finish;
  float spent_time;

  //prepare default args
  prog_args.if_name = "eth0";
  prog_args.dst_mac = "00:00:00:00:00:00";
  prog_args.msg_size = 256;
  prog_args.msg_count = 1;
  prog_args.pattern = 0x01;
  prog_args.use_udp = false;

  //read cli args
  opt = getopt(argc, argv, opt_string);
  while(opt != -1){
    switch(opt){
      case 'i': 
        prog_args.if_name = optarg;
        break;
      case 'd':
        prog_args.dst_mac = optarg;
        break;
      case 'b':
        scanf_result = sscanf(optarg, "%zu", &prog_args.msg_size);
        if(scanf_result != 1){
          printf("Wrong message size format!\n");
          display_usage();
          exit(EXIT_FAILURE);
        }
        if(!ETHER_IS_VALID_LEN(prog_args.msg_size)){
          printf("Message len must be \"%d <= len <= %d\"\n", ETH_ZLEN, ETH_DATA_LEN);
          exit(EXIT_FAILURE); 
        }
        break;
      case 't':
        scanf_result = sscanf(optarg, "%u", &prog_args.delay);
        break;
      case 'c':
        scanf_result = sscanf(optarg, "%zu", &prog_args.msg_count);
        if(scanf_result != 1){
          printf("Wrong message count format!\n");
          display_usage();
          exit(EXIT_FAILURE);
        }
        break;
      case 'p':
        scanf_result = sscanf(optarg, "%hhx", &prog_args.pattern);
        if(scanf_result != 1){
          printf("Wrong pattern format!\n");
          display_usage();
          exit(EXIT_FAILURE);
        }
        break;
      case 'u':
        prog_args.use_udp = true;
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
  
  //set destination mac addr
  if(ether_aton_r(prog_args.dst_mac, (struct ether_addr*)eh->ether_dhost) == NULL){
    printf("Wrong destination mac addr format!\n");
    display_usage();
    exit(EXIT_FAILURE);
  }


  //open socket
  if((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1){
    perror("socket");
    exit(EXIT_FAILURE);
  }

  strncpy(if_idx.ifr_name, prog_args.if_name, IFNAMSIZ-1);
  if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
    perror("SIOCGIFINDEX");
    exit(EXIT_FAILURE);
  }

  strncpy(if_mac.ifr_name, prog_args.if_name, IFNAMSIZ-1);
  if(ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0){
    perror("SIOCGIFHWADDR");
    exit(EXIT_FAILURE);
  }

  memcpy((void*)(eh->ether_shost), (void*)(if_mac.ifr_hwaddr.sa_data), ETH_ALEN);
  
  printf("source mac addr: %s\n", ether_ntoa((struct ether_addr*)eh->ether_shost));
  printf("destination mac addr: %s\n", ether_ntoa((struct ether_addr*)eh->ether_dhost));

  printf("msg pattern: %02hhx\n", prog_args.pattern);
  printf("msg size: %zu\n", prog_args.msg_size);
  printf("msg_count: %zu\n", prog_args.msg_count);

  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;
  memcpy((void*)(socket_address.sll_addr), (void*)(eh->ether_dhost), ETH_ALEN);
  
  eh->ether_type = htons(ETH_P_IP);
  //fill whole raw ethernet meaasge by pattern
  tx_len = sizeof(struct ether_header);
  while(tx_len < prog_args.msg_size + sizeof(struct ether_header)){
    sendbuf[tx_len] = prog_args.pattern;
    tx_len++; 
  }
  //here tx_len has actual value
  msg_count_ptr = (void*)sendbuf + sizeof(struct ether_header);

  if(prog_args.use_udp){
    //set headers to zeros
    bzero((void*)iph, sizeof(struct iphdr) + sizeof(struct udphdr));
    //write in ip header
    iph->ihl = 5; //header len (std)
    iph->version = 4;
    iph->tos = 16;
    //iph->frag_off = 0;
    iph->id = htons(34567);
    iph->ttl = IPDEFTTL;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = inet_addr("192.168.1.10");
    iph->daddr = inet_addr("192.168.1.20");

    //write in udp header
    udph->source = htons(32154);
    udph->dest = htons(32154);
    udph->len = htons(prog_args.msg_size - sizeof(struct iphdr));
    udph->check = checksum((unsigned short*)udph, (prog_args.msg_size - sizeof(struct iphdr)/2));

    //write in ip hdr len
    iph->tot_len = htons(prog_args.msg_size);
    iph->check = checksum((unsigned short*)iph, (sizeof(struct iphdr)/2));

    msg_count_ptr = (void*)sendbuf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
  }
  
  
  msg_count = 0;

  clock_gettime(CLOCK_REALTIME, &start);
  while(msg_count < prog_args.msg_count){
    //*msg_count_ptr = msg_count;
    send_count = sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
    usleep(prog_args.delay);
    if(send_count < 0){
      msg_count_fault++;
    }
    msg_count++;
  }
  clock_gettime(CLOCK_REALTIME, &finish);
  spent_time = (float)((finish.tv_sec * 1000000000 + finish.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec))/1000000000.0;

  printf("%zu frames for %f sec\ntotal rate: %f bps, payload rate: %f bps\n", 
      msg_count - msg_count_fault, 
      spent_time, 
      (prog_args.msg_size + 14) * (msg_count - msg_count_fault)*8/spent_time,
      (prog_args.msg_size) * (msg_count - msg_count_fault)*8/spent_time);
  clock_getres(CLOCK_REALTIME, &finish);
  printf("clock resolution: %zu sec %zu nsec\n", finish.tv_sec, finish.tv_nsec);
  return 0;
}
