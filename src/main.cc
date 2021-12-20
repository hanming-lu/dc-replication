#include <cassert>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <zmq.hpp>

#include "config.h"
#include "capsule.pb.h"
#include "crypto_util.hpp"
#include "storage.hpp"
#include "util/logging.hpp"

/* Admin Server */

int run_admin_server()
{
    /*
    (v2 Todo)
    Setup:
    1. Register with multicast tree
    2. Start thread for listening for data server connection 
    3. Start thread for failure recovery  
    */

    return 0;
}

/* Data Server */

int data_server_setup()
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

    // initiate rocksDB for disk storage
    std::string storage_path = "/tmp/testdb";
    Storage storage = Storage(storage_path);

    // test: Insert value
    std::string dummy_key = "dummy_key";
    capsule::CapsulePDU dummy_dc;
    bool res = storage.put(dummy_key, &dummy_dc);
    assert(res == true);

    // test: Read back value
    res = storage.get(dummy_key, &dummy_dc);
    assert(res == true);

    // test: Read key which does not exist
    std::string DNE_key = "DNE_key";
    res = storage.get(DNE_key, &dummy_dc);
    assert(res == false);

    return 0;
}

int data_server_handle_msg()
{
    /*
    Data Server Handling:
    1. Receive a mcast msg (i.e. a record)
    2. Decrypt (if needed)
    2. Recompute its hash & verify signature
    3. Find its parent using prevHash
    4. Append it to its parent & store on disk
    5. send signed ack to leader
    */

    // Todo: receive msg from mcast
    capsule::CapsulePDU dummy_dc;
    std::string msg;
    dummy_dc.SerializeToString(&msg);

    capsule::CapsulePDU in_dc;
    in_dc.ParseFromString(msg);

    // verify signature
    std::string dummy_verifyKey = "verifyKey";
    if (verify_dc(&in_dc, dummy_verifyKey) != true)
        Logger::log(LogLevel::ERROR, "DataCapsule Record Verification Failed.");

    // find its parent in the chain
    // if (chainDB.get(in_dc.prevHash) == false)
    //   Logger.log(LogLevel::WARNING, "DataCapsule Record's prevHash not found.");

    // Append the record to the chain
    // chainDB.put(hash, in_dc);

    // send signed ack to leader
    // ack = "dummyack"
    // std::string dummy_signKey = "signKey";
    // signed_ack = sign(ack, dummy_signKey)
    // send(leader_addr, signed_ack)

    return 0;
}

int data_server_leader_handle_ack()
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

int run_data_server()
{
    // Data Server Setup
    data_server_setup();

    // Leader Ack Handle (a new thread)
    data_server_leader_handle_ack();

    // Data Server Handle
    while (true)
    {
        data_server_handle_msg();
    }

    return 0;
}

int thread_start_listen_mcast()
{
    // Create a socket (IPv4, TCP)
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        std::cout << "Failed to create socket. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    // Listen to port 9999 on any address
    sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = INADDR_ANY;
    sockaddr.sin_port = htons(9999); // htons is necessary to convert a number to
                                     // network byte order
    if (bind(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
    {
        std::cout << "Failed to bind to port 9999. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    // Start listening. Hold at most 10 connections in the queue
    if (listen(sockfd, 10) < 0)
    {
        std::cout << "Failed to listen on socket. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    // Grab a connection from the queue
    auto addrlen = sizeof(sockaddr);
    int connection = accept(sockfd, (struct sockaddr *)&sockaddr, (socklen_t *)&addrlen);
    if (connection < 0)
    {
        std::cout << "Failed to grab connection. errno: " << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    // Read from the connection
    char buffer[100];
    auto bytesRead = read(connection, buffer, 100);
    std::cout << "The message was: " << buffer;

    // Send a message to the connection
    std::string response = "Good talking to you\n";
    send(connection, response.c_str(), response.size(), 0);

    // Close the connections
    close(connection);
    close(sockfd);

    return 0;
}

int main(int argc, char *argv[])
{
    /*
    1. start admin server thread
    2. start data server threads
    */

    return 0;
}