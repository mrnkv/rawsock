#ifndef __UTILS_H__
#define __UTILS_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#define INTERFACE_NAME_LEN 10


struct prog_args_t{
  char high_end_if[IFNAMSIZ];
  char low_end_if[IFNAMSIZ];
  int high_speed;
  int low_speed;
} prog_args_t;


void parse_args(int argc, char **argv, struct prog_args_t *args);
int get_sock_fd(char *if_name);
void prepare_flow_control_pkt(uint8_t *pkt);
void set_flow_ctrl_delay(uint8_t *pkt, uint16_t delay);

#endif
