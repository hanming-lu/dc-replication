#include "dc_client.hpp"

#include <string>
#include <thread>

#include "capsule.pb.h"
#include "request.pb.h"
#include "config.h"
#include "crypto.hpp"
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

#if TEST_MODE
    /* 
    Client send base case:
     1. create several dummy dc's
     2. sign and encrypt the dc's
     3. send dc's via network to all dc servers
    */
    task_threads.push_back(std::thread(&DC_Client::client_send_base_run, this));
    
    /* 
    Client get requests:
     1. create several dummy get requests
     2. send dc's via network to a random dc server
    */
    std::this_thread::sleep_for(std::chrono::seconds(10)); // wait for put to finish
    task_threads.push_back(std::thread(&DC_Client::client_get_req_run, this));
#endif

#if BENCHMARK_MODE
    task_threads.push_back(std::thread(&DC_Client::benchmark_run, this));
#endif

    /*
    (DONE) 
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
     3. send dc's via network to proxy port (proxy in enclave so it is trusted to multicast to dc servers)
     4. proxy verifies signatures
     5. proxy encrypt via hmac and mcast dc's to dc servers
     6. dc servers decrypt hmac
     6a. hmac can verify both data integrity and authenticity of a message
    */

   /* 
    Client recv optimization #2 - hmac & proxy in enclave:
     1. dc servers encrypt and send via hmac to proxy
     2. proxy receives acks from all dc servers via hmac
     4. proxy sends ack back to client
     5. client receives ack. Do not need to verify because proxy is in enclave.
     5b. If proxy is not in enclave, an ack still needs a threshold signature from several dc servers for a quorum.
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
    
    int count = 0;
    std::string dummy_payload = "dummy_payload";
    for (int i = 0; i < 10; i++)
    {
        put(std::to_string(count), dummy_payload);
        count++;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    put("last_hash", dummy_payload);

    return 0;
}

int DC_Client::client_get_req_run()
{
    /* 
    Client get requests:
     1. create several dummy get requests
     2. send dc's via network to a random dc server
    */

    for (int i = 1; i < 6; i++) 
    {
        get(std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    freshness_get();

    return 0;
}

#if BENCHMARK_MODE
#include "benchmark.h"
#else
void DC_Client::benchmark_run(){}
#endif // BENCHMARK_MODE

void DC_Client::put(std::string hash, std::string payload)
{
    /*
    Constructs a dc:
    1. hash = hash
    2. payload_in_transit = encrypt_message(payload)
    */
    capsule::CapsulePDU out_dc;
    std::string enc_payload = crypto.encrypt_message(payload);
    out_dc.set_payload_in_transit(enc_payload);
    out_dc.set_sender(1);
    out_dc.set_prevhash(m_prev_hash);
    out_dc.set_msglen(payload.length());
    out_dc.set_replyaddr(client_comm.m_recv_ack_addr);
    out_dc.set_hash(hash);

    m_prev_hash = hash;
    
#if OUTGOING_MODE == 1 or OUTGOING_MODE == 2
    sign_dc(&out_dc, &this->crypto);
#elif OUTGOING_MODE == 3
    std::string c_digest = crypto.c_hmac_sha256(
        out_dc.payload_in_transit().c_str(), 
        out_dc.payload_in_transit().length());
    out_dc.set_payload_hmac(c_digest);
#endif

    std::string out_msg;
    out_dc.SerializeToString(&out_msg);

#if OUTGOING_MODE == 1 or OUTGOING_MODE == 2
    client_comm.mcast_dc(out_msg);
#elif OUTGOING_MODE == 3
    client_comm.send_dc_proxy(out_msg);
#endif
}

void DC_Client::get(std::string hash)
{
    capsule::ClientGetRequest out_req;
    out_req.set_hash(hash);
    out_req.set_replyaddr(client_comm.m_recv_get_resp_addr);
    std::string out_msg;
    out_req.SerializeToString(&out_msg);

    client_comm.send_get_req(out_msg);
}

void DC_Client::freshness_get()
{
    capsule::ClientGetRequest out_req;
    out_req.set_fresh_req(true);
    out_req.set_replyaddr(client_comm.m_recv_get_resp_addr);
    std::string out_msg;
    out_req.SerializeToString(&out_msg);

    client_comm.send_get_req(out_msg);
}