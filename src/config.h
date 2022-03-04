#ifndef __CONFIG_H
#define __CONFIG_H

#define DEBUG_MODE false
#define INTEGRATED_MODE true

// For leader/follower DC networking
#define NET_DC_SERVER_IP "localhost" // my IP
#define NET_LEADER_DC_SERVER_IPs "localhost,localhost" // comma-separated leader IPs
#define NET_LEADER_DC_SERVER_RECV_ACK_PORT 4000 
#define NET_DC_SERVER_BASE_PORT 4001

// For mcast networking
#define NET_SEED_ROUTER_IP "localhost"
#define NET_SERVER_JOIN_PORT 6666
#define NET_SERVER_MCAST_PORT 6667

// Global Config
#define VERIFY_SIG_PER_WRITES 5
#define WRITE_THRESHOLD 3
#define REPLICATION_ACK "REPLICATION_ACK"
#define REPLICATION_ID 4999

// Local Config for leader
#define HAS_LEADER_LOCAL true
#define LEADER_ID_LOCAL 100

// Local Config for DC servers
#define LOCAL_DC_SERVER_COUNT 3
#define INIT_DC_SERVER_ID 101

#endif // __CONFIG_H
