#include <chrono>
#include <utility>
#include <stdlib.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <zmq.hpp>

#include "capsule.pb.h"
#include "crypto_util.hpp"
#include "pairing.pb.h"
#include "request.pb.h"
#include "comm.hpp"
#include "dc_server.hpp"
#include "util/logging.hpp"
#include "util/utils.hpp"

Comm::Comm(std::string ip, int64_t server_id, bool is_leader, DC_Server *dc_server)
    : m_context(1)
{
    m_ip = ip;
    m_port = (is_leader) ? std::to_string(NET_LEADER_DC_SERVER_RECV_ACK_PORT) : std::to_string(NET_DC_SERVER_BASE_PORT + server_id);
    m_addr = "tcp://" + m_ip + ":" + m_port;
    m_pairing_port = std::to_string(NET_DC_SERVER_PAIRING_BASE_PORT + server_id);
    m_pairing_addr = m_ip + ":" + m_pairing_port;
    m_serve_port = std::to_string(NET_SERVE_PORT + server_id);
    m_dc_server = dc_server;

    size_t last = 0;
    size_t next = 0;
#if OUTGOING_MODE == 2
    // initialize leader addrs
    std::string leader_ips = NET_LEADER_DC_SERVER_IPs;
    std::string delim = ",";
    last = 0;
    next = 0;
    while ((next = leader_ips.find(delim, last)) != std::string::npos)
    {
        m_leader_dc_server_addrs.push_back(leader_ips.substr(last, next - last) + ":" + m_leader_dc_server_recv_ack_port);
        last = next + delim.length();
    }
    m_leader_dc_server_addrs.push_back(leader_ips.substr(last) + ":" + m_leader_dc_server_recv_ack_port);

    Logger::log(LogLevel::DEBUG, "[DC SERVER] Number of collectors: " + std::to_string(m_leader_dc_server_addrs.size()));
#endif

    // initialize pairing addrs and sockets
    std::string pair_ips = NET_PAIRING_DC_SERVER_IPs;
    std::string ip_delim = ",";
    std::string count_delim = ":";
    std::vector<std::pair<std::string, int> > pair_ip_count;
    last = 0;
    next = 0;
    while ((next = pair_ips.find(ip_delim, last)) != std::string::npos)
    {
        std::string ip_count = pair_ips.substr(last, next - last);
        int pos = ip_count.find(count_delim);
        pair_ip_count.push_back(std::make_pair(ip_count.substr(0, pos), std::stoi(ip_count.substr(pos + 1))));
        last = next + ip_delim.length();
    }
    std::string ip_count = pair_ips.substr(last);
    int pos = ip_count.find(count_delim);
    pair_ip_count.push_back(std::make_pair(ip_count.substr(0, pos), std::stoi(ip_count.substr(pos + 1))));

    for (auto &p : pair_ip_count)
    {
        for (int i = INIT_DC_SERVER_ID; i < p.second + INIT_DC_SERVER_ID; i++)
        {
            std::string pairing_addr = p.first + ":" + std::to_string(NET_DC_SERVER_PAIRING_BASE_PORT + i);
            if (pairing_addr == m_pairing_addr)
                continue;
            zmq::socket_t *socket_send_pair_msg = new zmq::socket_t(m_context, ZMQ_PUSH);
            socket_send_pair_msg->connect("tcp://" + pairing_addr);

            m_pair_dc_server_sockets.emplace(pairing_addr, socket_send_pair_msg);
        }
    }

    Logger::log(LogLevel::DEBUG, "[DC SERVER] Number of pairing destinations: " + std::to_string(m_pair_dc_server_sockets.size()));

#if OUTGOING_MODE == 3
    // initialize proxy mcast socket
    std::string proxy_join_mcast_addr = (std::string) NET_PROXY_IP + ":" + std::to_string(NET_PROXY_RECV_DC_SERVER_JOIN_PORT);
    zmq::socket_t *proxy_join_mcast_socket = new zmq::socket_t(m_context, ZMQ_PUSH);
    proxy_join_mcast_socket->connect("tcp://" + proxy_join_mcast_addr);
    send_string(m_addr, proxy_join_mcast_socket);
    Logger::log(LogLevel::DEBUG, "[DC SERVER] connected to proxy for mcast: " + proxy_join_mcast_addr);

    // initialize proxy ack socket
    std::string proxy_ack_addr = (std::string) NET_PROXY_IP + ":" + std::to_string(NET_PROXY_RECV_ACK_PORT);
    m_proxy_ack_socket = new zmq::socket_t(m_context, ZMQ_PUSH);
    m_proxy_ack_socket->connect("tcp://" + proxy_ack_addr);
    Logger::log(LogLevel::DEBUG, "[DC SERVER] connected to proxy for acks: " + proxy_ack_addr);
#endif

}

void Comm::run_leader_dc_server_handle_ack_opt1() // only run when OUTGOING_MODE == 2
{
    /* 
    Client recv optimization #1 - one ack:
     1. dc servers sign their acks
     2. proxy receives acks from all dc servers
     3. proxy verifies all acks
     4. proxy creates a threshold signature 
     5. proxy sends back to client
     6. client decrypt and verify the ack
    */
    std::unordered_map<std::string, zmq::socket_t *> socket_send_ack_map;
    // socket to recv acks
    zmq::socket_t socket_recv_acks(m_context, ZMQ_PULL);
    socket_recv_acks.bind("tcp://*:" + std::to_string(NET_LEADER_DC_SERVER_RECV_ACK_PORT));

    // poll ack messages
    std::vector<zmq::pollitem_t> pollitems = {
        {static_cast<void *>(socket_recv_acks), 0, ZMQ_POLLIN, 0},
    };

    Logger::log(LogLevel::DEBUG, "[DC Proxy] run_leader_dc_server_handle_ack_opt1() start polling.");
    while (true)
    {
        zmq::poll(pollitems.data(), pollitems.size(), 0);
        // Received an ack from dc server
        if (pollitems[0].revents & ZMQ_POLLIN)
        {
            std::string in_msg = this->recv_string(&socket_recv_acks);
            Logger::log(LogLevel::DEBUG, "[DC Proxy] Received ack message: " + in_msg);
            capsule::CapsulePDU in_ack_dc;
            in_ack_dc.ParseFromString(in_msg);
            verify_dc(&in_ack_dc, &(m_dc_server->crypto));
            std::string sender_hash = std::to_string(in_ack_dc.sender()) + in_ack_dc.hash();
            Logger::log(LogLevel::DEBUG, "[DC Proxy] Received ack sender_hash: " + sender_hash);

            // Store to a local unordered_map of acks
            this->ack_map[sender_hash] += 1;

            // send ack back to client if a threshold is reached
            if (this->ack_map[sender_hash] == WRITE_THRESHOLD)
            {
                Logger::log(LogLevel::DEBUG, "[DC Proxy] ack reached WRITE_THRESHOLD for sender_hash: " + sender_hash);
                this->ack_map[sender_hash] = 0;
                sign_dc(&in_ack_dc, &(m_dc_server->crypto));
                std::string out_msg;
                in_ack_dc.SerializeToString(&out_msg);
                const std::string &replyaddr = in_ack_dc.replyaddr();

                Logger::log(LogLevel::DEBUG, "[DC Proxy] sending ack to replyaddr: "+ replyaddr);

                // check if replyaddr is in socket_send_ack_map, if not, create a new connection
                auto got = socket_send_ack_map.find(replyaddr);
                if ( got == socket_send_ack_map.end() )
                {
                    zmq::socket_t *socket_send_ack = new zmq::socket_t(m_context, ZMQ_PUSH);
                    socket_send_ack->connect("tcp://" + replyaddr);
                    socket_send_ack_map[replyaddr] = socket_send_ack;
                    Logger::log(LogLevel::DEBUG, "[DC Proxy] Connected to Client for ack. Addr: "+ replyaddr);
                }

                this->send_string(out_msg, socket_send_ack_map[replyaddr]);
                Logger::log(LogLevel::DEBUG, "[DC Proxy] Sent an ack msg: " + out_msg +
                                                " to client: " + replyaddr);
            }
        }
    }
}

void Comm::run_dc_server_listen_mcast_and_client()
{
    // to receive mcast msg from mcast server
    zmq::socket_t socket_from_mcast(m_context, ZMQ_PULL);
    socket_from_mcast.bind("tcp://*:" + m_port);
    // to receive get (i.e. serve) requests from clients
    zmq::socket_t socket_serve_client(m_context, ZMQ_PULL);
    socket_serve_client.bind("tcp://*:" + m_serve_port);

    // poll for new messages
    std::vector<zmq::pollitem_t> pollitems = {
        {static_cast<void *>(socket_from_mcast), 0, ZMQ_POLLIN, 0},
        {static_cast<void *>(socket_serve_client), 0, ZMQ_POLLIN, 0 },
    };

    Logger::log(LogLevel::DEBUG, "[DC SERVER] run_dc_server_listen_mcast_and_client() start polling.");
    while (true)
    {
        zmq::poll(pollitems.data(), pollitems.size(), 0);
        /* mcast */
        if (pollitems[0].revents & ZMQ_POLLIN)
        {
            // Received a msg from mcast
            std::string msg = this->recv_string(&socket_from_mcast);
            capsule::CapsulePDU in_dc;
            in_dc.ParseFromString(msg);
            if (in_dc.msgtype() != REPLICATION_ACK)
            {
                // Put mcast msg to mcast_q
                this->m_dc_server->mcast_q_enqueue(msg);

                Logger::log(LogLevel::DEBUG, "[DC SERVER] Received & put a mcast message: " + msg);
            }
        }
        /* serve client get request */
        if (pollitems[1].revents & ZMQ_POLLIN) 
        {
            std::string msg = this->recv_string(&socket_serve_client);
            // put request to serve_req_q
            this->m_dc_server->serve_req_q_enqueue(msg);
            Logger::log(LogLevel::DEBUG, "[DC SERVER] Received & put a serve message: " + msg);
        }
    }
}

void Comm::run_dc_server_send_ack_to_replyaddr() // only run when OUTGOING_MODE == 1
{
    std::unordered_map<std::string, zmq::socket_t *> socket_send_ack_map;

    while (true)
    {
        std::string out_msg = this->m_dc_server->ack_q_dequeue();
        if (out_msg == "")
            continue;

        capsule::CapsulePDU out_ack_dc;
        out_ack_dc.ParseFromString(out_msg);

        const std::string &replyaddr = out_ack_dc.replyaddr();
        Logger::log(LogLevel::DEBUG, "[DC SERVER] sending ack to replyaddr: "+ replyaddr);

        // check if replyaddr is in socket_send_ack_map, if not, create a new connection
        auto got = socket_send_ack_map.find(replyaddr);
        if ( got == socket_send_ack_map.end() )
        {
            zmq::socket_t *socket_send_ack = new zmq::socket_t(m_context, ZMQ_PUSH);
            socket_send_ack->connect("tcp://" + replyaddr);
            socket_send_ack_map[replyaddr] = socket_send_ack;
            Logger::log(LogLevel::DEBUG, "[DC SERVER] Connected to Client for ack. Addr: "+ replyaddr);
        }

        this->send_string(out_msg, socket_send_ack_map[replyaddr]);
        Logger::log(LogLevel::DEBUG, "[DC SERVER] Sent an ack msg: " + out_msg +
                                         " to client: " + replyaddr);
    }

    for (auto &p : socket_send_ack_map)
    {
        delete p.second;
    }
}

void Comm::run_dc_server_send_ack_to_leader() // only run when OUTGOING_MODE == 2
{
    std::vector<zmq::socket_t *> socket_send_ack_l;
    for (auto &addr : m_leader_dc_server_addrs)
    {
        zmq::socket_t *socket_send_ack = new zmq::socket_t(m_context, ZMQ_PUSH);
        socket_send_ack->connect("tcp://" + addr);
        socket_send_ack_l.push_back(socket_send_ack);
    }

    Logger::log(LogLevel::DEBUG, "[DC SERVER] Connected to Leader DC Server for acks");
    while (true)
    {
        std::string out_msg = this->m_dc_server->ack_q_dequeue();
        if (out_msg == "")
            continue;

        capsule::CapsulePDU out_ack_dc;
        out_ack_dc.ParseFromString(out_msg);

        int send_ack_to_leader_num = Utils::hashToInt(out_ack_dc.hash(), socket_send_ack_l.size());

        this->send_string(out_msg, socket_send_ack_l[send_ack_to_leader_num]);
        Logger::log(LogLevel::DEBUG, "[DC SERVER] Sent an ack msg: " + out_msg +
                                         " to leader_num: " + std::to_string(send_ack_to_leader_num));
    }

    for (auto &socket : socket_send_ack_l)
    {
        delete socket;
    }
}

void Comm::run_dc_server_send_ack_to_proxy() // only run when OUTGOING_MODE == 3
{
    while (true)
    {
        std::string out_msg = this->m_dc_server->ack_q_dequeue();
        if (out_msg == "")
            continue;

        this->send_string(out_msg, m_proxy_ack_socket);
        Logger::log(LogLevel::DEBUG, "[DC SERVER] Sent an ack msg: " + out_msg + " to proxy.");
    }
}

void Comm::run_dc_server_send_serve_resp()
{
    std::unordered_map<std::string, zmq::socket_t *> socket_send_serve_resp_map;

    while (true)
    {
        std::string out_msg = this->m_dc_server->serve_resp_q_dequeue();
        if (out_msg == "")
            continue;

        capsule::ClientGetResponse serve_resp;
        serve_resp.ParseFromString(out_msg);

        const std::string &target_addr = serve_resp.targetaddr();
        Logger::log(LogLevel::DEBUG, "[DC SERVER] target_addr for get resp: "+ target_addr);

        // check if target_addr is in socket_send_serve_resp_map, if not, create a new connection
        auto got = socket_send_serve_resp_map.find(target_addr);
        if ( got == socket_send_serve_resp_map.end() )
        {
            zmq::socket_t *socket_send_serve_resp = new zmq::socket_t(m_context, ZMQ_PUSH);
            socket_send_serve_resp->connect("tcp://" + target_addr);
            socket_send_serve_resp_map[target_addr] = socket_send_serve_resp;
            Logger::log(LogLevel::DEBUG, "[DC SERVER] Connected to Client for get responses. Addr: "+ target_addr);
        }
        this->send_string(out_msg, socket_send_serve_resp_map[target_addr]);
        Logger::log(LogLevel::DEBUG, "[DC SERVER] Sent a get response msg: " + out_msg +
                                         " to client: " + target_addr);
    }

    for (auto &socket : socket_send_serve_resp_map)
    {
        delete socket.second;
    }
}

void Comm::run_dc_server_listen_pairing_msg()
{
    // to receive pairing request/response
    zmq::socket_t socket_from_pairing(m_context, ZMQ_PULL);
    socket_from_pairing.bind("tcp://*:" + m_pairing_port);

    // poll for new messages
    std::vector<zmq::pollitem_t> pollitems = {
        {static_cast<void *>(socket_from_pairing), 0, ZMQ_POLLIN, 0},
    };

    Logger::log(LogLevel::INFO, "[DC Pairing] start listening to pairing requests/responses: " + m_pairing_addr);
    while (true)
    {
        zmq::poll(pollitems.data(), pollitems.size(), 0);

        if (pollitems[0].revents & ZMQ_POLLIN)
        {
            // Received a request/response from pairing
            std::string msg = this->recv_string(&socket_from_pairing);
            // Put request/response to pairing_q
            this->m_dc_server->pairing_q_enqueue(msg);

            Logger::log(LogLevel::DEBUG, "[DC Pairing] Received & put a pairing request/response: " + msg);
        }
    }
}

void Comm::send_dc_server_pairing_request(std::unordered_set<std::string> &sources,
                                          std::unordered_set<std::string> &sinks)
{
    capsule::PairingWrapperMsg pair_msg;
    capsule::PairingRequest pair_req;
    std::string pair_msg_s;

    if (m_pair_dc_server_sockets.size() < 1)
        return;

    // serialize sources, sinks, reply_addr to PairingRequest
    *pair_req.mutable_sources() = {sources.begin(), sources.end()};
    *pair_req.mutable_sinks() = {sinks.begin(), sinks.end()};
    pair_req.set_replyaddr(m_pairing_addr);

    // apply wrapper
    *pair_msg.mutable_request() = pair_req;
    pair_msg.SerializeToString(&pair_msg_s);

    // send to a randomly selected pairing server
    auto it = std::next(
        std::begin(m_pair_dc_server_sockets),
        rand() % m_pair_dc_server_sockets.size());

    this->send_string(pair_msg_s, it->second);
    Logger::log(LogLevel::DEBUG, "[DC Pairing] Sent a pairing request from: " + m_pairing_addr +
                                     " to: " + it->first + ". Sources size: " + std::to_string(sources.size()) +
                                     " Sinks size: " + std::to_string(sinks.size()));

    return;
}

void Comm::send_dc_server_pairing_response(
    std::vector<capsule::CapsulePDU> &records_to_return,
    const std::string &reply_addr)
{

    // wrap PairingResponse in PairingWrapperMsg
    capsule::PairingWrapperMsg pair_msg;
    capsule::PairingResponse pair_resp;
    std::string pair_msg_s;
    *pair_resp.mutable_records() = {records_to_return.begin(), records_to_return.end()};
    *pair_msg.mutable_response() = pair_resp;
    pair_msg.SerializeToString(&pair_msg_s);

    // add reply_addr socket if it does not exist
    if (m_pair_dc_server_sockets.find(reply_addr) == m_pair_dc_server_sockets.end())
    {
        zmq::socket_t *socket_send_pair_msg = new zmq::socket_t(m_context, ZMQ_PUSH);
        socket_send_pair_msg->connect("tcp://" + reply_addr);
        m_pair_dc_server_sockets.emplace(reply_addr, socket_send_pair_msg);

        Logger::log(LogLevel::DEBUG, "[DC Pairing] Added connection for pairing to addr: " + reply_addr);
    }

    // send records to reply_addr
    auto it = m_pair_dc_server_sockets.find(reply_addr);
    this->send_string(pair_msg_s, it->second);
    Logger::log(LogLevel::DEBUG, "[DC Pairing] Sent a pairing response: " + pair_msg_s +
                                     " from: " + m_pairing_addr + " to: " + reply_addr);

    return;
}