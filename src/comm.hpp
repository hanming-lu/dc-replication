#ifndef __COMM_H
#define __COMM_H

#include <string>
#include <unordered_map>
#include <vector>
#include <zmq.hpp>

#include "config.h"
#include "dc_server.hpp"

class Comm
{
public:
    Comm(std::string ip, int64_t server_id, bool is_leader, DC_Server* dc_server);

    void run_leader_dc_server_handle_ack();
    void run_dc_server_listen_mcast();
    void run_dc_server_send_ack_to_leader();

private:
    DC_Server* m_dc_server;
    std::string m_ip;
    std::string m_port;
    std::string m_addr;
    std::vector<std::string> m_leader_dc_server_addrs;
    std::string m_leader_dc_server_recv_ack_port = std::to_string(NET_LEADER_DC_SERVER_RECV_ACK_PORT);
    std::unordered_map<std::string, int> ack_map;

    // For mcast
    std::string m_seed_server_ip = NET_SEED_ROUTER_IP;
    std::string m_seed_server_join_port = std::to_string(NET_SERVER_JOIN_PORT);
    std::string m_seed_server_mcast_port = std::to_string(NET_SERVER_MCAST_PORT);

    zmq::message_t string_to_message(const std::string& s) {
        zmq::message_t msg(s.size());
        memcpy(msg.data(), s.c_str(), s.size());
        return msg;
    }

    std::string message_to_string(const zmq::message_t& message) {
        return std::string(static_cast<const char*>(message.data()), message.size());
    }
    std::string recv_string(zmq::socket_t* socket) {
        zmq::message_t message;
        socket->recv(&message);
        return this->message_to_string(message);
    }
    void send_string(const std::string& s, zmq::socket_t* socket) {
        socket->send(string_to_message(s));
    }
};

#endif // __COMM_H