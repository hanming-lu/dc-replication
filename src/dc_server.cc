#include "capsule.pb.h"
#include "crypto_util.hpp"
#include "dc_server.hpp"
#include "storage.hpp"
#include "util/logging.hpp"

DC_Server::DC_Server(const int64_t server_id,
                     const std::string storage_path) : server_id(server_id), storage(Storage(storage_path))
{
    // initiate storage
}

int DC_Server::dc_server_setup()
{
    /* 
    Setup:
    1. Leader election (v2 Todo)
    2. Register with admin (v2 Todo)
    2.1 Get Leader's address from admin (v2 Todo)
    3. Register with multicast tree (v2 Todo)
    4. Initiate a on-disk database (a hashtable for v1)
    5. Start listening for multicast message
    */

    return 0;
}

int DC_Server::dc_server_run()
{
    /*
    DC Server Handling:
    1. Receive a mcast msg (i.e. a record)
    2. Decrypt (if needed)
    2. Recompute its hash & verify signature
    3. Find its parent using prevHash
    4. Append it to its parent & store on disk
    5. send signed ack to leader
    */

    // Todo: Implement threading
    listen_mcast();
    handle_mcast_msg();
    send_ack_to_leader();

    // Todo: wait on send_ack_to_leader's thread

    return 0;
}

int DC_Server::dc_server_leader_run()
{
    /*
    Leader Ack Handling:
    1. Listen for acks from followers
    2. Verify ack signature
    3. Store in a on-memory hashtable
    4. When a threshold of acks is reached, send threshold signature back to client
    */
    return 0;
}

int DC_Server::listen_mcast()
{
    // // Create a socket (IPv4, TCP)
    // int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // if (sockfd == -1)
    // {
    //     std::cout << "Failed to create socket. errno: " << errno << std::endl;
    //     exit(EXIT_FAILURE);
    // }

    // // Listen to port 9999 on any address
    // sockaddr_in sockaddr;
    // sockaddr.sin_family = AF_INET;
    // sockaddr.sin_addr.s_addr = INADDR_ANY;
    // sockaddr.sin_port = htons(9999); // htons is necessary to convert a number to
    //                                  // network byte order
    // if (bind(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
    // {
    //     std::cout << "Failed to bind to port 9999. errno: " << errno << std::endl;
    //     exit(EXIT_FAILURE);
    // }

    // // Start listening. Hold at most 10 connections in the queue
    // if (listen(sockfd, 10) < 0)
    // {
    //     std::cout << "Failed to listen on socket. errno: " << errno << std::endl;
    //     exit(EXIT_FAILURE);
    // }

    // // Grab a connection from the queue
    // auto addrlen = sizeof(sockaddr);
    // int connection = accept(sockfd, (struct sockaddr *)&sockaddr, (socklen_t *)&addrlen);
    // if (connection < 0)
    // {
    //     std::cout << "Failed to grab connection. errno: " << errno << std::endl;
    //     exit(EXIT_FAILURE);
    // }

    // // Read from the connection
    // char buffer[100];
    // auto bytesRead = read(connection, buffer, 100);
    // std::cout << "The message was: " << buffer;

    // // Send a message to the connection
    // std::string response = "Good talking to you\n";
    // send(connection, response.c_str(), response.size(), 0);

    // // Close the connections
    // close(connection);
    // close(sockfd);

    return 0;
}

int DC_Server::handle_mcast_msg()
{
    while (true)
    {
        std::string in_msg;
        {
            std::lock_guard<std::mutex> lock_guard(this->mcast_msg_q_mutex);
            if (!this->mcast_msg_q.empty())
            {
                in_msg = this->mcast_msg_q.front();
                this->mcast_msg_q.pop();
            }
            else
            {
                continue;
            }
        }

        capsule::CapsulePDU in_dc;
        in_dc.ParseFromString(in_msg);

        // verify signature
        if (verify_dc(&in_dc, verifying_key) != true)
        {
            Logger::log(LogLevel::ERROR, "DataCapsule Record Verification Failed. Hash: " + in_dc.hash());
            continue;
        }

        // find its parent in the chain
        capsule::CapsulePDU unused_dc;
        bool sucess = storage.get(in_dc.prevhash(), &unused_dc);
        if (!sucess && (in_dc.prevhash() != "init"))
        {
            Logger::log(LogLevel::WARNING, "DataCapsule Record's prevHash not found, skipped. PrevHash: " + in_dc.prevhash());
            continue;
        }

        // Append the record to the chain
        sucess = storage.put(in_dc.hash(), &in_dc);
        if (!sucess)
        {
            Logger::log(LogLevel::WARNING, "Append DataCapsule FAILED, skipped. Hash: " + in_dc.hash());
            continue;
        }

        // append signed ack to ack_q
        capsule::CapsulePDU ack_dc;
        ack_dc.set_sender(server_id);
        ack_dc.set_hash(in_dc.hash());
        sign_dc(&ack_dc, this->signing_key);

        {
            std::lock_guard<std::mutex> lock_guard(this->ack_q_mutex);
            this->ack_q.emplace(ack_dc);
        }
    }
    return 0;
}

int DC_Server::send_ack_to_leader()
{
    while (true)
    {
        capsule::CapsulePDU in_ack_dc;
        {
            std::lock_guard<std::mutex> lock_guard(this->ack_q_mutex);
            if (!this->ack_q.empty())
            {
                in_ack_dc = this->ack_q.front();
                this->ack_q.pop();
            }
            else
            {
                continue;
            }
        }

        // Todo: send to leader
    }
}