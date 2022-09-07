#ifndef __CONFIG_H
#define __CONFIG_H

// THESE SHOULD BE TRUE BEFORE COMMIT
#define INTEGRATED_MODE false

// THESE SHOULD BE FALSE BEFORE COMMIT
#define DEBUG_MODE true
#define INITIATE_EMPTY_DB true // WARNING: IF TRUE, THIS WILL DELETE db_path DB if it already exists

// For leader/follower DC networking
#define NET_DC_SERVER_IP "localhost"            // my IP
#define NET_LEADER_DC_SERVER_IPs "localhost"    // comma-separated leader IPs (e.g. 128.32.37.26,128.32.37.46)
#define NET_PAIRING_DC_SERVER_IPs "localhost:3" // comma-separated "pairing peer IP:server count there" (e.g. 128.32.37.26:3,128.32.37.46:2)
#define NET_LEADER_DC_SERVER_RECV_ACK_PORT 4000
#define NET_DC_SERVER_BASE_PORT 4001
#define NET_DC_SERVER_PAIRING_BASE_PORT 4500

// For mcast networking
#define NET_SEED_ROUTER_IP "localhost"
#define NET_SERVER_JOIN_PORT 6666
#define NET_SERVER_MCAST_PORT 6667

// For serving get request from clients
#define NET_SERVE_PORT 4300

// Global Config
#define VERIFY_SIG_PER_WRITES 5
#define WRITE_THRESHOLD 3
#define REPLICATION_ACK "REPLICATION_ACK"
#define REPLICATION_ID 4999
#define PAIRING_TIMEOUT_SEC 5

// Local Config for leader
#define HAS_LEADER_LOCAL true
#define LEADER_ID_LOCAL 100

// Local Config for DC servers
#define LOCAL_DC_SERVER_COUNT 3
#define INIT_DC_SERVER_ID 101

#endif // __CONFIG_H
