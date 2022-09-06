#ifndef __DCSERVER_H
#define __DCSERVER_H

#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "pairing.pb.h"
#include "comm.hpp"
#include "crypto.hpp"
#include "storage.hpp"

class DC_Server
{
public:
    DC_Server(const int64_t server_id, const bool is_leader,
              const std::string storage_path);

    int dc_server_run();

    void mcast_q_enqueue(const std::string &mcast_msg);
    std::string mcast_q_dequeue();

    void serve_req_q_enqueue(const std::string &serve_msg);
    std::string serve_req_q_dequeue();

    void serve_resp_q_enqueue(const std::string &serve_msg);
    std::string serve_resp_q_dequeue();

    void ack_q_enqueue(const std::string &ack_msg);
    std::string ack_q_dequeue();

    void pairing_q_enqueue(const std::string &pairing_msg);
    std::string pairing_q_dequeue();

    void handle_pairing_request(const capsule::PairingRequest &req);
    void handle_pairing_response(const capsule::PairingResponse &resp);

private:
    Crypto crypto;
    int64_t server_id;
    bool is_leader;
    Comm comm;

    Storage storage;
    std::mutex storage_mutex;
    std::unordered_map<std::string, int> unverified_count; // count the number of unverified record before it (inclusive)

    std::queue<std::string> mcast_q;
    std::mutex mcast_q_mutex;
    std::queue<std::string> serve_req_q;
    std::mutex serve_req_q_mutex;
    std::queue<std::string> serve_resp_q;
    std::mutex serve_resp_q_mutex;
    std::queue<std::string> ack_q;
    std::mutex ack_q_mutex;
    std::queue<std::string> pairing_q;
    std::mutex pairing_q_mutex;

    // For mcast msg
    int thread_listen_mcast_and_client();
    int thread_handle_mcast_msg();
    // For get request msg
    int thread_handle_serve_request_msg();
    int thread_send_serve_resp();
    // For collector acks
    int thread_send_ack_to_leader();
    int thread_leader_handle_ack();
    // For anti-entropy pairing
    int thread_initiate_pairing();
    int thread_listen_pairing_msg();
    int thread_handle_pairing_msg();
};

#endif // __DCSERVER_H