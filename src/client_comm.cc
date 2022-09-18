#include "client_comm.hpp"

#include <cstdlib>

#include "capsule.pb.h"
#include "request.pb.h"
#include "config.h"
#include "crypto_util.hpp"
#include "dc_client.hpp"
#include "util/logging.hpp"

ClientComm::ClientComm(std::string ip, int64_t client_id, DC_Client *dc_client)
    : m_context(1)
{
    m_ip = ip;
    m_recv_ack_port = std::to_string(NET_CLIENT_RECV_ACK_PORT + client_id);
    m_recv_ack_addr = m_ip + ":" + m_recv_ack_port;
    m_recv_get_resp_port = std::to_string(NET_CLIENT_RECV_GET_RESP_PORT + client_id);
    m_recv_get_resp_addr = m_ip + ":" + m_recv_get_resp_port;
    m_dc_client = dc_client;

    // initialize server addrs and sockets
    std::string server_ips = NET_PAIRING_DC_SERVER_IPs; // use pairing ips
    std::string ip_delim = ",";
    std::string count_delim = ":";
    std::vector<std::pair<std::string, int> > server_ip_count;
    int last = 0;
    int next = 0;
    while ((next = server_ips.find(ip_delim, last)) != std::string::npos)
    {
        std::string ip_count = server_ips.substr(last, next - last);
        int pos = ip_count.find(count_delim);
        server_ip_count.push_back(std::make_pair(ip_count.substr(0, pos), std::stoi(ip_count.substr(pos + 1))));
        last = next + ip_delim.length();
    }
    std::string ip_count = server_ips.substr(last);
    int pos = ip_count.find(count_delim);
    server_ip_count.push_back(std::make_pair(ip_count.substr(0, pos), std::stoi(ip_count.substr(pos + 1))));

    // initialize dc server dc sockets
    for (auto &p : server_ip_count)
    {
        for (int i = INIT_DC_SERVER_ID; i < p.second + INIT_DC_SERVER_ID; i++)
        {
            std::string server_addr = p.first + ":" + std::to_string(NET_DC_SERVER_BASE_PORT + i);
            zmq::socket_t *socket_send_dc = new zmq::socket_t(m_context, ZMQ_PUSH);
            socket_send_dc->connect("tcp://" + server_addr);

            m_dc_server_dc_sockets.emplace(server_addr, socket_send_dc);
            Logger::log(LogLevel::DEBUG, "[DC CLIENT] connected to server for dc: " + server_addr);
        }
    }
    // initialize dc server serve sockets
    for (auto &p : server_ip_count)
    {
        for (int i = INIT_DC_SERVER_ID; i < p.second + INIT_DC_SERVER_ID; i++)
        {
            std::string server_addr = p.first + ":" + std::to_string(NET_SERVE_PORT + i);
            zmq::socket_t *socket_send_dc = new zmq::socket_t(m_context, ZMQ_PUSH);
            socket_send_dc->connect("tcp://" + server_addr);

            m_dc_server_serve_sockets.emplace(server_addr, socket_send_dc);
            Logger::log(LogLevel::DEBUG, "[DC CLIENT] connected to server for serve get: " + server_addr);
        }
    }

    Logger::log(LogLevel::DEBUG, "[DC CLIENT] Number of server destinations: " + std::to_string(m_dc_server_dc_sockets.size()));
}

void ClientComm::send_dc(std::string &msg) 
{
    for (auto &p : m_dc_server_dc_sockets)
    {
        send_string(msg, p.second);
        Logger::log(LogLevel::DEBUG, "[DC CLIENT] Sent dc to server: " + p.first + ", dc: " + msg);
    }
}

void ClientComm::send_get_req(std::string &msg) 
{
    auto random_it = std::next(
        std::begin(m_dc_server_serve_sockets), 
        rand() % m_dc_server_serve_sockets.size()
    );

    send_string(msg, random_it->second);
    Logger::log(LogLevel::DEBUG, "[DC CLIENT] Sent get req to server: " + random_it->first + ", msg: " + msg);
}

void ClientComm::run_dc_client_listen_server()
{   
    // to receive ack msg from dc servers
    zmq::socket_t socket_for_ack(m_context, ZMQ_PULL);
    socket_for_ack.bind("tcp://*:" + m_recv_ack_port);
    // to receive get response from dc servers
    zmq::socket_t socket_for_get_resp(m_context, ZMQ_PULL);
    socket_for_get_resp.bind("tcp://*:" + m_recv_get_resp_port);

    // poll for new messages
    std::vector<zmq::pollitem_t> pollitems = {
        {static_cast<void *>(socket_for_ack), 0, ZMQ_POLLIN, 0},
        {static_cast<void *>(socket_for_get_resp), 0, ZMQ_POLLIN, 0},
    };

    Logger::log(LogLevel::DEBUG, "[DC CLIENT] run_dc_client_listen_server() start polling.");
    while (true)
    {
        zmq::poll(pollitems.data(), pollitems.size(), 0);
        /* ack */
        if (pollitems[0].revents & ZMQ_POLLIN)
        {
            // Received an ack
            std::string msg = this->recv_string(&socket_for_ack);
            capsule::CapsulePDU ack_dc;
            ack_dc.ParseFromString(msg);
            assert (ack_dc.msgtype() == REPLICATION_ACK);

            if (verify_dc(&ack_dc, &(m_dc_client->crypto)) != true)
            {
                Logger::log(LogLevel::INFO, "[DC CLIENT] Received an ack, verification Failed. Hash: " + ack_dc.hash());
            }
            else
            {
                Logger::log(LogLevel::DEBUG, "[DC CLIENT] Received an ack, verification Successful. Hash: " + ack_dc.hash());
            }
            
            m_recv_ack_map[ack_dc.hash()] += 1;
#if OUTGOING_MODE == 1
            // receive acks directly from dc servers
            if (m_recv_ack_map[ack_dc.hash()] == WRITE_THRESHOLD) {
                Logger::log(LogLevel::DEBUG, "[DC CLIENT] ack message reached threshold for hash: " + ack_dc.hash());
            }
#elif OUTGOING_MODE == 2
            // receive acks from proxy
            Logger::log(LogLevel::DEBUG, "[DC CLIENT] received ack message from proxy for hash: " + ack_dc.hash());
#endif
            
        }
        /* get response */
        if (pollitems[1].revents & ZMQ_POLLIN) 
        {
            // Received a get response
            std::string msg = this->recv_string(&socket_for_get_resp);
            capsule::ClientGetResponse resp;
            resp.ParseFromString(msg);

            std::string succ = resp.success() ? "true" : "false";
            Logger::log(LogLevel::DEBUG, "[DC CLIENT] Received get response for hash: " + resp.hash() + ", succ: " + succ);
        }
    }
}