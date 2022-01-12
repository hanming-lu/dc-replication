#include <chrono>
#include <string>
#include <thread>
#include <zmq.hpp>

#include "capsule.pb.h"
#include "comm.hpp"
#include "config.h"
#include "crypto_util.hpp"
#include "dc_server.hpp"
#include "storage.hpp"
#include "util/logging.hpp"

DC_Server::DC_Server(const int64_t server_id,
                     const std::string storage_path) : server_id(server_id), storage(Storage(storage_path))
// initiate on-disk storage
{
    // v2 Todo: select the first server as leader for now
    this->is_leader = (server_id == INIT_DC_SERVER_ID) ? true : false;
}

int DC_Server::dc_server_setup()
{
    /* 
    Setup:
    1. Leader election (v2 Todo)
    2. Register with admin (v2 Todo)
    2.1 Get Leader's address from admin (v2 Todo)
    3. Register with multicast tree (integration)
    */

    return 0;
}

int DC_Server::dc_server_run()
{
    std::vector<std::thread> task_threads;

    // thread to start leader ack handling
    if (this->is_leader)
    {
        task_threads.push_back(std::thread(&DC_Server::thread_leader_handle_ack, this));
    }
    // Let leader get ready for DC server connections
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    // thread to receive msg from mcast
    task_threads.push_back(std::thread(&DC_Server::thread_listen_mcast, this));
    // thread to handle msg from mcast, generate ack
    task_threads.push_back(std::thread(&DC_Server::thread_handle_mcast_msg, this));
    // thread to send acks to leader
    task_threads.push_back(std::thread(&DC_Server::thread_send_ack_to_leader, this));

    // Wait for all tasks to finish
    for (auto &t : task_threads)
    {
        t.join();
    }

    return 0;
}

int DC_Server::thread_listen_mcast()
{
    /*
    DC Server Listen Multicast:
    While true:
    1. Receive a mcast msg from network
    2. add it to mcast_q
    */
    Logger::log(LogLevel::INFO, "DC Server starts receiving multicast msgs, dc server #" + std::to_string(this->server_id));

#if INTEGRATED_MODE == false
    std::string cur_prevHash = "init";
    int count = 0;
    for (int i = 0; i < 10; i++)
    {
        capsule::CapsulePDU dummy_dc;
        dummy_dc.set_prevhash(cur_prevHash);
        cur_prevHash = std::to_string(count++);
        dummy_dc.set_hash(cur_prevHash);
        std::string dummy_msg;
        dummy_dc.SerializeToString(&dummy_msg);
        this->mcast_q_enqueue(dummy_msg);

        Logger::log(LogLevel::DEBUG, "Put a mcast msg");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
#endif

    Comm comm = Comm(NET_DC_SERVER_IP, this->server_id, this);
    comm.run_dc_server_listen_mcast();

    return 0;
}

int DC_Server::thread_handle_mcast_msg()
{
    /*
    DC Server Handling:
    While true:
    1. get a mcast msg from mcast_q
    2. Decrypt (if needed)
    2. Recompute its hash & verify signature
    3. Find its parent using prevHash
    4. Append it to its parent & store on disk
    5. send signed ack to leader
    */
    Logger::log(LogLevel::DEBUG, "thread_handle_mcast_msg() running, dc server #" + std::to_string(this->server_id));

    while (true)
    {
        std::string in_msg = mcast_q_dequeue();
        if (in_msg == "")
        {
            Logger::log(LogLevel::DEBUG, "mcast msg queue is empty");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        else
        {
            Logger::log(LogLevel::DEBUG, "Received a mcast msg: " + in_msg);
        }

        capsule::CapsulePDU in_dc;
        in_dc.ParseFromString(in_msg);

        // verify signature
        if (verify_dc(&in_dc, verifying_key) != true)
        {
            Logger::log(LogLevel::ERROR, "DataCapsule Record Verification Failed. Hash: " + in_dc.hash());
            continue;
        } else {
            Logger::log(LogLevel::DEBUG, "DataCapsule Record Verification Successful. Hash: " + in_dc.hash());
        }

        // find its parent in the chain
        capsule::CapsulePDU unused_dc;
        if (in_dc.prevhash() == "") continue;
        bool success = storage.get(in_dc.prevhash(), &unused_dc);
        if (!success && (in_dc.prevhash() != "init"))
        {
            Logger::log(LogLevel::DEBUG, "DataCapsule Record's prevHash not found, but stored anyway. PrevHash: " + in_dc.prevhash());
            // continue;
        } else {
            Logger::log(LogLevel::DEBUG, "Found prevHash for Hash: " + in_dc.hash());
        }

        // Append the record to the chain
        success = storage.put(in_dc.hash(), &in_dc);
        if (!success)
        {
            Logger::log(LogLevel::WARNING, "Append DataCapsule FAILED, skipped. Hash: " + in_dc.hash());
            continue;
        } else {
            Logger::log(LogLevel::DEBUG, "Successfully appended Hash: " + in_dc.hash());
        }

        // append signed ack to ack_q
        capsule::CapsulePDU ack_dc;
        ack_dc.set_sender(in_dc.sender());
        ack_dc.set_hash(in_dc.hash());
        ack_dc.set_msgtype(REPLICATION_ACK);
        sign_dc(&ack_dc, this->signing_key);
        std::string ack_msg;
        ack_dc.SerializeToString(&ack_msg);

        // enqueue ack_msg
        this->ack_q_enqueue(ack_msg);
    }
    return 0;
}

int DC_Server::thread_send_ack_to_leader()
{
    Logger::log(LogLevel::DEBUG, "thread_send_ack_to_leader() running, dc server #" + std::to_string(this->server_id));
    Comm comm = Comm(NET_DC_SERVER_IP, this->server_id, this);
    comm.run_dc_server_send_ack_to_leader();

    return 0;
}

int DC_Server::thread_leader_handle_ack()
{
    /*
    Leader Ack Handling:
    1. Listen for acks from followers
    2. Verify ack signature
    3. Store in a on-memory hashtable
    4. When a threshold of acks is reached, send threshold signature back to client
    */
    Logger::log(LogLevel::INFO, "Leader DC Server starts receiving acks, dc server #" + std::to_string(this->server_id));
    Comm comm = Comm(NET_DC_SERVER_IP, this->server_id, this);
    comm.run_leader_dc_server_handle_ack();

    return 0;
}

void DC_Server::mcast_q_enqueue(const std::string& mcast_msg)
{
    std::lock_guard<std::mutex> lock_guard(this->mcast_q_mutex);
    this->mcast_q.push(mcast_msg);
}

std::string DC_Server::mcast_q_dequeue()
{
    std::lock_guard<std::mutex> lock_guard(this->mcast_q_mutex);
    std::string in_msg = "";
    if (!this->mcast_q.empty())
    {
        in_msg = this->mcast_q.front();
        this->mcast_q.pop();
    }
    return in_msg;
}

void DC_Server::ack_q_enqueue(const std::string& ack_msg)
{
    std::lock_guard<std::mutex> lock_guard(this->ack_q_mutex);
    this->ack_q.push(ack_msg);
}

std::string DC_Server::ack_q_dequeue()
{
    std::lock_guard<std::mutex> lock_guard(this->ack_q_mutex);
    std::string out_msg = "";
    if (!this->ack_q.empty())
    {
        out_msg = this->ack_q.front();
        this->ack_q.pop();
    }
    return out_msg;
}