#ifndef __DCSERVER_H
#define __DCSERVER_H

#include <mutex>
#include <queue>
#include "storage.hpp"

class DC_Server
{
public:
    DC_Server(const int64_t server_id, const std::string storage_path);

    int dc_server_setup();

    int dc_server_run();

    int dc_server_leader_run();

private:
    Storage storage;
    int64_t server_id;
    std::string signing_key = "dummy_signing_key";
    std::string verifying_key = "dummy_verifying_key";
    std::queue<std::string> mcast_msg_q;
    std::mutex mcast_msg_q_mutex;
    std::queue<capsule::CapsulePDU> ack_q;
    std::mutex ack_q_mutex;

    int listen_mcast();
    int handle_mcast_msg();
    int send_ack_to_leader();
};

#endif // __DCSERVER_H