#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <poll.h>

#include "utils.h"

#define BUF_SIZE    65537

int main (int argc, char **argv){

  uint8_t low_speed_buf[BUF_SIZE];
  uint8_t high_speed_buf[BUF_SIZE];
  uint8_t flow_ctrl_buf[ETH_ZLEN];
  int numbytes = 0;
  int speed_factor;

  struct prog_args_t global_args;
  parse_args(argc, argv, &global_args);

  speed_factor = global_args.high_speed / global_args.low_speed;

  uint16_t low_if_tick = speed_factor * (global_args.cpu_freq/global_args.high_speed);
  

  printf ("SETTINGS: \n\thigh_end: %s\n\tspeed: %d\n\tlow_end: %s\n\tspeed: %d\nspeed factor:%d\n\tCPU freq: %d\n", 
      global_args.high_end_if,
      global_args.high_speed,
      global_args.low_end_if,
      global_args.low_speed,
      speed_factor,
      global_args.cpu_freq);
  printf("\tlow if tick: %u\n", low_if_tick);


  int low_speed_fd = get_sock_fd(global_args.low_end_if);
  if (low_speed_fd < 0){
    printf ("Can't open low speed nic. Error code: %d\n", low_speed_fd);
    return EXIT_FAILURE;
  }

  int high_speed_fd = get_sock_fd(global_args.high_end_if);
  if(high_speed_fd < 0){
    printf ("Can't open high speed nic. Error code: %d\n", high_speed_fd);
    return EXIT_FAILURE;
  }

  prepare_flow_control_pkt(flow_ctrl_buf);

  struct pollfd fds[2];
  fds[0].fd = low_speed_fd;
  fds[0].events = POLLIN;
  fds[1].fd = high_speed_fd;
  fds[1].events = POLLIN;
  
  while(1){
    int ret = poll(fds, 2, 100000);
    if(ret == -1){
      perror("Polling error.");
      return EXIT_FAILURE;
    }
    if(ret == 0){
      printf("\nPoll timeout\n");
      return EXIT_SUCCESS;
    }
    if(fds[0].revents & POLLIN){
      numbytes = recvfrom(low_speed_fd, low_speed_buf, BUF_SIZE, 0, NULL, NULL);
      //fprintf(stderr, ".");
     /* 
      set_flow_ctrl_delay(flow_ctrl_buf, 65535);
      write(low_speed_fd, flow_ctrl_buf, ETH_ZLEN);
      */
      write(high_speed_fd, low_speed_buf, numbytes);
/*
      set_flow_ctrl_delay(flow_ctrl_buf, 0);
      write(low_speed_fd, flow_ctrl_buf, ETH_ZLEN);
      */
    }
    if(fds[1].revents & POLLIN){
      numbytes = recvfrom(high_speed_fd, high_speed_buf, BUF_SIZE, 0, NULL, NULL);
      //fprintf(stderr, "+");
      if ( speed_factor != 1){
        set_flow_ctrl_delay(flow_ctrl_buf, 0xffff);
        write(high_speed_fd, flow_ctrl_buf, ETH_ZLEN);
      }
      uint64_t current = rdtsc();
      uint64_t next = current + numbytes * low_if_tick;
      //printf("%lu\t %d\n", next - current, numbytes);
      write(low_speed_fd, high_speed_buf, numbytes);

      if (speed_factor != 1){
        //usleep((useconds_t)(numbytes/3));
        while(rdtsc() < next);
        set_flow_ctrl_delay(flow_ctrl_buf, 0);
        write(high_speed_fd, flow_ctrl_buf, ETH_ZLEN);
      }
    }
    //fprintf(stderr, "=");
  }

  close(low_speed_fd);

  return EXIT_SUCCESS;
}
