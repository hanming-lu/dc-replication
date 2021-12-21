#include <chrono>
#include <string>
#include <thread>
#include <zmq.hpp>

#include "capsule.pb.h"
#include "crypto_util.hpp"
#include "dc_server.hpp"
#include "storage.hpp"
#include "util/logging.hpp"

DC_Server::DC_Server(const int64_t server_id,
                     const std::string storage_path) : server_id(server_id), storage(Storage(storage_path))
{
    // initiate on-disk storage
}

int DC_Server::dc_server_setup()
{
    /* 
    Setup:
    1. Leader election (v2 Todo)
    2. Register with admin (v2 Todo)
    2.1 Get Leader's address from admin (v2 Todo)
    3. Register with multicast tree (v2 Todo)
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

    std::vector<std::thread> task_threads;

    // thread to receive msg from mcast
    task_threads.push_back(std::thread(&DC_Server::thread_listen_mcast, this));
    // thread to handle msg from mcast, generate ack
    task_threads.push_back(std::thread(&DC_Server::thread_handle_mcast_msg, this));
    // thread to start leader ack handling
    if (this->is_leader)
    {
        task_threads.push_back(std::thread(&DC_Server::thread_leader_handle_ack, this));
    }

    // Wait for all tasks to finish
    for (auto &t : task_threads)
    {
        t.join();
    }

    return 0;
}

int DC_Server::thread_listen_mcast()
{
    while (true)
    {
        capsule::CapsulePDU dummy_dc;
        dummy_dc.set_prevhash("init");
        std::string dummy_msg;
        dummy_dc.SerializeToString(&dummy_msg);

        {
            std::lock_guard<std::mutex> lock_guard(this->mcast_msg_q_mutex);
            this->mcast_msg_q.push(dummy_msg);
        }
        Logger::log(LogLevel::DEBUG, "Put a mcast msg");
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}

int DC_Server::thread_handle_mcast_msg()
{
    while (true)
    {
        std::string in_msg;
        this->mcast_msg_q_mutex.lock();
        if (!this->mcast_msg_q.empty())
        {
            in_msg = this->mcast_msg_q.front();
            this->mcast_msg_q.pop();
            this->mcast_msg_q_mutex.unlock();
            Logger::log(LogLevel::DEBUG, "Received a mcast msg");
        }
        else
        {
            this->mcast_msg_q_mutex.unlock();
            Logger::log(LogLevel::DEBUG, "mcast msg queue is empty");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
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
        bool success = storage.get(in_dc.prevhash(), &unused_dc);
        if (!success && (in_dc.prevhash() != "init"))
        {
            Logger::log(LogLevel::WARNING, "DataCapsule Record's prevHash not found, skipped. PrevHash: " + in_dc.prevhash());
            continue;
        }

        // Append the record to the chain
        success = storage.put(in_dc.hash(), &in_dc);
        if (!success)
        {
            Logger::log(LogLevel::WARNING, "Append DataCapsule FAILED, skipped. Hash: " + in_dc.hash());
            continue;
        }

        // append signed ack to ack_q
        capsule::CapsulePDU ack_dc;
        ack_dc.set_sender(server_id);
        ack_dc.set_hash(in_dc.hash());
        sign_dc(&ack_dc, this->signing_key);

        // Todo: send ack_dc to leader

    }
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
    return 0;
}