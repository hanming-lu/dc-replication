#ifndef __COMM_H
#define __COMM_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <zmq.hpp>

#include "capsule.pb.h"
#include "pairing.pb.h"
#include "config.h"

class DC_Server; // Forward Declaration to avoid circular dependency

class Comm
{
public:
    Comm(std::string ip, int64_t server_id, bool is_leader, DC_Server *dc_server);

    void run_leader_dc_server_handle_ack_opt1();
    void run_dc_server_listen_mcast_and_client();
    void run_dc_server_send_ack_to_replyaddr();
    void run_dc_server_send_ack_to_leader();
    void run_dc_server_send_ack_to_proxy();
    void run_dc_server_send_serve_resp();

    /* anti-entropy pairing */
    void run_dc_server_listen_pairing_msg();
    void send_dc_server_pairing_request(
        std::unordered_set<std::string> &sources,
        std::unordered_set<std::string> &sinks);
    void send_dc_server_pairing_response(
        std::vector<capsule::CapsulePDU> &records_to_return,
        const std::string &reply_addr);

private:
    DC_Server *m_dc_server;
    std::string m_ip;
    std::string m_port;
    std::string m_addr;
    std::string m_pairing_port;
    std::string m_pairing_addr;
    std::string m_serve_port;
    zmq::context_t m_context;
    std::vector<std::string> m_leader_dc_server_addrs;
    std::unordered_map<std::string, zmq::socket_t *> m_pair_dc_server_sockets;
    std::string m_leader_dc_server_recv_ack_port = std::to_string(NET_LEADER_DC_SERVER_RECV_ACK_PORT);
    zmq::socket_t * m_proxy_ack_socket;
    std::unordered_map<std::string, int> ack_map;

    zmq::message_t string_to_message(const std::string &s)
    {
        zmq::message_t msg(s.size());
        memcpy(msg.data(), s.c_str(), s.size());
        return msg;
    }

    std::string message_to_string(const zmq::message_t &message)
    {
        return std::string(static_cast<const char *>(message.data()), message.size());
    }
    std::string recv_string(zmq::socket_t *socket)
    {
        zmq::message_t message;
        socket->recv(&message);
        return this->message_to_string(message);
    }
    void send_string(const std::string &s, zmq::socket_t *socket)
    {
        socket->send(string_to_message(s));
    }
};

#endif // __COMM_H