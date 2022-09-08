#include "dc_client.hpp"

#include <string>
#include <thread>

#include "capsule.pb.h"
#include "request.pb.h"
#include "config.h"
#include "crypto_util.hpp"
#include "util/logging.hpp"

DC_Client::DC_Client(const int64_t client_id) : 
    crypto(Crypto()), 
    client_comm(ClientComm(NET_DC_SERVER_IP, client_id, this))
{}

int DC_Client::dc_client_run()
{
    /* DC Client */
    Logger::log(LogLevel::INFO, "DC_Client running");

    std::vector<std::thread> task_threads;
    
    /*
    Client recv base case:
     1. open a reply port to wait for acks
     2. receive all acks from all dc servers
     3. decrypt and verify all acks
    */
    task_threads.push_back(std::thread(&DC_Client::thread_listen_server, this));
    /* 
    Client send base case:
     1. create several dummy dc's
     2. sign and encrypt the dc's
     3. send dc's via network to all dc servers
    */
    task_threads.push_back(std::thread(&DC_Client::client_send_base_run, this));
    
    /* wait for send to finish, then get */
    std::this_thread::sleep_for(std::chrono::seconds(10));
    task_threads.push_back(std::thread(&DC_Client::client_get_req_run, this));

    /* 
    Client send optimization #1 - mcast:
     1. create several dummy dc's
     2. sign and encrypt the dc's
     3. send dc's via network to proxy port
     4. proxy mcast dc's to dc servers
     5. dc servers verify signatures
    */

    /* 
    Client recv optimization #1 - one ack:
     1. dc servers sign their acks
     2. proxy receives acks from all dc servers
     3. proxy verifies all acks
     4. proxy creates a threshold signature 
     5. proxy sends back to client
     6. client decrypt and verify the ack
    */

    /* 
    Client send optimization #2 - hmac & proxy in enclave:
     1. create several dummy dc's
     2. sign and encrypt the dc's
     3. send dc's via network to proxy port
     4. proxy verifies signatures
     5. proxy mcast dc's to dc servers via hmac
     6. dc servers do not verify because of hmac & proxy is trustworthy
    */

   /* 
    Client recv optimization #2 - hmac & proxy in enclave:
     1. dc servers do not sign because of hmac & proxy is trustworthy
     2. proxy receives acks from all dc servers via hmac
     3. proxy creates a signature 
     4. proxy sends back to client
     5. client decrypt and verify the ack
    */

    // Wait for all tasks to finish
    for (auto &t : task_threads)
    {
        t.join();
    }

    return 0;
}

int DC_Client::thread_listen_server()
{
    client_comm.run_dc_client_listen_server();

    return 0;
}

int DC_Client::client_send_base_run()
{
    /* 
    Client send base case:
     1. create several dummy dc's
     2. sign and encrypt the dc's
     3. send dc's via network to all dc servers
    */
    std::string cur_prevHash = "init";
    int test_sender = 001;
    int count = 0;
    for (int i = 0; i < 10; i++)
    {
        capsule::CapsulePDU dummy_dc;
        std::string payload = "dummy_payload";
        std::string enc_payload = crypto.encrypt_message(payload);
        dummy_dc.set_payload_in_transit(enc_payload);
        dummy_dc.set_sender(test_sender);
        dummy_dc.set_prevhash(cur_prevHash);
        dummy_dc.set_msglen(payload.length());
        dummy_dc.set_replyaddr(client_comm.m_recv_ack_addr);
        cur_prevHash = std::to_string(count++);
        dummy_dc.set_hash(cur_prevHash);
        sign_dc(&dummy_dc, &this->crypto);
        std::string dummy_msg;
        dummy_dc.SerializeToString(&dummy_msg);

        Logger::log(LogLevel::DEBUG, "[DC Client] Putting a dc to client_comm: " + dummy_msg);
        client_comm.send_dc(dummy_msg);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return 0;
}

int DC_Client::client_get_req_run()
{
    /* 
    Client get requests:
     1. create several dummy get requests
     2. send dc's via network to a random dc server
    */

    for (int i = 0; i < 5; i++) 
    {
        capsule::ClientGetRequest in_req;
        in_req.set_hash(std::to_string(i));
        in_req.set_replyaddr(client_comm.m_recv_get_resp_addr);
        std::string msg;
        in_req.SerializeToString(&msg);

        Logger::log(LogLevel::DEBUG, "[DC Client] Sending a get req to client_comm for hash: " + in_req.hash());
        client_comm.send_get_req(msg);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}