#ifndef __CONFIG_H
#define __CONFIG_H

#define DEBUG_MODE false
#define TEST_ON false

// For leader/follower DC networking
#define NET_DC_SERVER_IP "localhost"
#define NET_LEADER_DC_SERVER_IP "localhost"
#define NET_DC_SERVER_BASE_PORT 5001
#define NET_LEADER_DC_SERVER_RECV_ACK_PORT 4001

// For mcast networking
#define NET_SEED_ROUTER_IP "localhost"
#define NET_SERVER_JOIN_PORT 6666
#define NET_SERVER_MCAST_PORT 6667

#define INIT_DC_SERVER_ID 100
#define TOTAL_DC_SERVER 3
#define WRITE_THRESHOLD 2

#endif // __CONFIG_H