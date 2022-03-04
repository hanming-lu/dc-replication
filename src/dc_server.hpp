#ifndef __DCSERVER_H
#define __DCSERVER_H

#include <mutex>
#include <queue>
#include <string>

#include "crypto.hpp"
#include "storage.hpp"

class DC_Server
{
public:
    DC_Server(const int64_t server_id, const bool is_leader,
              const std::string storage_path);

    int dc_server_setup();
    int dc_server_run();
        
    void mcast_q_enqueue(const std::string& mcast_msg);
    std::string mcast_q_dequeue();

    void ack_q_enqueue(const std::string& ack_msg);
    std::string ack_q_dequeue();

private:
    Storage storage;
    Crypto crypto;
    int64_t server_id;
    bool is_leader;
    std::unordered_map<std::string, int> unverified_count; // count the number of unverified record before it (inclusive)
    std::queue<std::string> mcast_q;
    std::mutex mcast_q_mutex;
    std::queue<std::string> ack_q;
    std::mutex ack_q_mutex;

    int thread_listen_mcast();
    int thread_handle_mcast_msg();
    int thread_send_ack_to_leader();
    int thread_leader_handle_ack();

};

#endif // __DCSERVER_H