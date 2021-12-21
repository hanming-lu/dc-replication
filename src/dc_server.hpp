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

private:
    Storage storage;
    int64_t server_id;
    bool is_leader = false;
    std::string signing_key = "dummy_signing_key";
    std::string verifying_key = "dummy_verifying_key";
    std::queue<std::string> mcast_msg_q;
    std::mutex mcast_msg_q_mutex;

    int thread_listen_mcast();
    int thread_handle_mcast_msg();
    int thread_leader_handle_ack();
};

#endif // __DCSERVER_H