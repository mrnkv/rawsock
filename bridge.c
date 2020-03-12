#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_ether.h>

#include "utils.h"

#define BUF_SIZE    65537

int main (int argc, char **argv){

  uint8_t low_speed_buf[BUF_SIZE];
  uint8_t high_speed_buf[BUF_SIZE];
  uint8_t flow_ctrl_buf[ETH_ZLEN];
  int pckt_count;
  int numbytes = 0;
  int speed_factor;

  struct prog_args_t global_args;
  parse_args(argc, argv, &global_args);

  speed_factor = global_args.high_speed / global_args.low_speed;

  printf ("SETTINGS: \n\thigh_end: %s\n\tspeed: %d\n\tlow_end: %s\n\tspeed: %d\nspeed factor:%d\n", 
      global_args.high_end_if,
      global_args.high_speed,
      global_args.low_end_if,
      global_args.low_speed,
      speed_factor);


  int low_speed_fd = get_sock_fd(global_args.low_end_if);
  if (low_speed_fd < 0){
    printf ("Error code: %d\n", low_speed_fd);
    return EXIT_FAILURE;
  }

  prepare_flow_control_pkt(flow_ctrl_buf);
  
  while(pckt_count < 2000){
    numbytes = recvfrom(low_speed_fd, low_speed_buf, BUF_SIZE, 0, NULL, NULL);
    printf("Packet number: %d packet len: %u\n", pckt_count, numbytes);
    pckt_count++;
    set_flow_ctrl_delay(flow_ctrl_buf, 65535);
    write(low_speed_fd, flow_ctrl_buf, ETH_ZLEN);
    usleep(8000);
    set_flow_ctrl_delay(flow_ctrl_buf, 0);
    write(low_speed_fd, flow_ctrl_buf, ETH_ZLEN);
  }

  close(low_speed_fd);

  return EXIT_SUCCESS;
}
