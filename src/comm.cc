#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include <zmq.hpp>

#include "capsule.pb.h"
#include "comm.hpp"
#include "util/logging.hpp"

Comm::Comm(std::string ip, const int64_t server_id, DC_Server *dc_server)
{
    m_ip = ip;
    m_port = std::to_string(NET_DC_SERVER_BASE_PORT + server_id);
    m_addr = "tcp://" + m_ip + ":" + m_port;
    m_dc_server = dc_server;
}

void Comm::run_leader_dc_server_handle_ack()
{
    zmq::context_t context(1);

    // socket to recv acks
    zmq::socket_t socket_recv_acks(context, ZMQ_PULL);
    socket_recv_acks.bind("tcp://*:" + std::to_string(NET_LEADER_DC_SERVER_RECV_ACK_PORT));

#if INTEGRATED_MODE == true
    // use multicast to send ack
    zmq::socket_t socket_send(context, ZMQ_PUSH);
    socket_send.connect("tcp://" + m_seed_server_ip + ":" + m_seed_server_mcast_port);
#endif

    // poll ack messages
    std::vector<zmq::pollitem_t> pollitems = {
        {static_cast<void *>(socket_recv_acks), 0, ZMQ_POLLIN, 0},
    };

    Logger::log(LogLevel::DEBUG, "[LEADER DC SERVER] run_leader_dc_server_handle_ack() start polling.");
    while (true)
    {
        zmq::poll(pollitems.data(), pollitems.size(), 0);
        // Received an ack from dc server
        if (pollitems[0].revents & ZMQ_POLLIN)
        {
            std::string in_msg = this->recv_string(&socket_recv_acks);
            Logger::log(LogLevel::DEBUG, "[LEADER DC SERVER] Received ack message: " + in_msg);
            capsule::CapsulePDU in_ack_dc;
            in_ack_dc.ParseFromString(in_msg);
            std::string sender_hash = std::to_string(in_ack_dc.sender()) + in_ack_dc.hash();

            // Store to a local unordered_map of acks
            this->ack_map[sender_hash] += 1;

            // send ack back to client if a threshold is reached
            if (this->ack_map[sender_hash] == WRITE_THRESHOLD)
            {
                Logger::log(LogLevel::DEBUG, "[LEADER DC SERVER] Write threshold reached for hash: " + sender_hash);
                this->ack_map[sender_hash] = 0;
#if INTEGRATED_MODE == true
                // use multicast to send ack
                this->send_string(in_msg, &socket_send);
#endif
            }
        }
    }
}

void Comm::run_dc_server_listen_mcast()
{
    zmq::context_t context(1);

    // to receive mcast msg from mcast server
    zmq::socket_t socket_from_mcast(context, ZMQ_PULL);
    socket_from_mcast.bind("tcp://*:" + m_port);

#if INTEGRATED_MODE == true
    zmq::socket_t socket_join(context, ZMQ_PUSH);
    socket_join.connect("tcp://" + m_seed_server_ip + ":" + m_seed_server_join_port);
    this->send_string(m_addr, &socket_join);
#endif

    // poll for new messages
    std::vector<zmq::pollitem_t> pollitems = {
        {static_cast<void *>(socket_from_mcast), 0, ZMQ_POLLIN, 0},
    };

    Logger::log(LogLevel::DEBUG, "[DC SERVER] run_dc_server_listen_mcast() start polling.");
    while (true)
    {
        zmq::poll(pollitems.data(), pollitems.size(), 0);

        if (pollitems[0].revents & ZMQ_POLLIN)
        {
            // Received a msg from mcast
            std::string msg = this->recv_string(&socket_from_mcast);
            capsule::CapsulePDU in_dc;
            in_dc.ParseFromString(msg);
            if (in_dc.msgtype() != REPLICATION_ACK) {
                // Put mcast msg to mcast_q
                this->m_dc_server->mcast_q_enqueue(msg);

                Logger::log(LogLevel::DEBUG, "[DC SERVER] Received & put a mcast message: " + msg);
            }
        }
    }
}

void Comm::run_dc_server_send_ack_to_leader()
{
    zmq::context_t context(1);
    zmq::socket_t socket_send_ack(context, ZMQ_PUSH);
    socket_send_ack.connect("tcp://" + m_leader_dc_server_ip + ":" + m_leader_dc_server_recv_ack_port);

    Logger::log(LogLevel::DEBUG, "[DC SERVER] Connected to Leader DC Server for acks");
    while (true)
    {
        std::string out_msg = this->m_dc_server->ack_q_dequeue();
        if (out_msg == "")
        {
            Logger::log(LogLevel::DEBUG, "ack q is empty");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        this->send_string(out_msg, &socket_send_ack);
        Logger::log(LogLevel::DEBUG, "[DC SERVER] Sent an ack msg: " + out_msg);
    }
}