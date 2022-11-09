#include <chrono>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <zmq.hpp>

#include "capsule.pb.h"
#include "pairing.pb.h"
#include "request.pb.h"
#include "comm.hpp"
#include "config.h"
#include "crypto.hpp"
#include "crypto_util.hpp"
#include "dc_server.hpp"
#include "storage.hpp"
#include "util/logging.hpp"

DC_Server::DC_Server(const int64_t server_id,
                     const bool is_leader,
                     const std::string storage_path) : server_id(server_id),
                                                       is_leader(is_leader),
                                                       storage(Storage(storage_path)),
                                                       crypto(Crypto()),
                                                       comm(Comm(NET_DC_SERVER_IP, server_id, is_leader, this))
{
}

int DC_Server::dc_server_run()
{
    std::vector<std::thread> task_threads;

    // thread to start leader ack handling
    if (this->is_leader)
    {
#if OUTGOING_MODE == 2
        /* Leader DC Server */
        task_threads.push_back(std::thread(&DC_Server::thread_leader_handle_ack, this));
#endif
    }
    else
    {
        /* DC Server */
        // thread to receive msg from mcast
        task_threads.push_back(std::thread(&DC_Server::thread_listen_mcast_and_client, this));
        // thread to handle msg from mcast, generate ack
        task_threads.push_back(std::thread(&DC_Server::thread_handle_mcast_msg, this));
#if OUTGOING_MODE == 1
        // thread to send acks to client
        task_threads.push_back(std::thread(&DC_Server::thread_send_ack_to_replyaddr, this));
#elif OUTGOING_MODE == 2
        // thread to send acks to leader
        task_threads.push_back(std::thread(&DC_Server::thread_send_ack_to_leader, this));
#elif OUTGOING_MODE == 3
        // thread to send acks to in-enclave proxy
        task_threads.push_back(std::thread(&DC_Server::thread_send_ack_to_proxy, this));
#endif
        // thread to handle get request from client
        task_threads.push_back(std::thread(&DC_Server::thread_handle_serve_request_msg, this));
        // thread to send get reponse to client
        task_threads.push_back(std::thread(&DC_Server::thread_send_serve_resp, this));

        // thread to initate pairing request when needed
        task_threads.push_back(std::thread(&DC_Server::thread_initiate_pairing, this));
        // thread to listen to incoming pairing msgs
        task_threads.push_back(std::thread(&DC_Server::thread_listen_pairing_msg, this));
        // thread to handle incoming pairing msgs
        task_threads.push_back(std::thread(&DC_Server::thread_handle_pairing_msg, this));
    }

    // Wait for all tasks to finish
    for (auto &t : task_threads)
    {
        t.join();
    }

    return 0;
}

int DC_Server::thread_listen_mcast_and_client()
{
    /*
    DC Server Listen Multicast:
    While true:
    1. Receive a mcast msg from network
    2. add it to mcast_q
    */
    Logger::log(LogLevel::INFO, "DC Server starts receiving multicast msgs, dc server #" + std::to_string(this->server_id));

    comm.run_dc_server_listen_mcast_and_client();

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
            continue;

        Logger::log(LogLevel::DEBUG, "Received a mcast msg: "); //+ in_msg);

        capsule::CapsulePDU in_dc;
        in_dc.ParseFromString(in_msg);

        //if (in_dc.header().prevhash() == "")
        //    continue;

        Logger::log(LogLevel::DEBUG, "prevhash checked "); //+ in_msg);
        capsule::CapsuleHeader *in_dc_header = in_dc.mutable_header();

#if OUTGOING_MODE == 1 or OUTGOING_MODE == 2
        verify_dc(&in_dc, &this->crypto);
//        in_dc_header->set_verified(true);
#elif OUTGOING_MODE == 3
        // verify hmac digest
        std::string s_digest_expected = crypto.s_hmac_sha256(
            in_dc.payload_in_transit().c_str(), 
            in_dc.payload_in_transit().length()
        );
        if (s_digest_expected == in_dc.payload_hmac())
        {
            Logger::log(LogLevel::DEBUG, "[DC SERVER] Received a write, HMAC verification Successful. Hash: " + in_dc.hash());
        }
        else
        {
            Logger::log(LogLevel::INFO, "[DC SERVER] Received a write, HMAC verification Failed, hash: " + in_dc.hash() +
                "\nExpected HMAC: " + s_digest_expected +
                "\nReceived HMAC: " + in_dc.payload_hmac()
            );
        }

        // periodically verify signature
        bool to_verify = false;

        // find parent's unverified count
        // note that unverified_count is not persisted, so valid parent's hash may not be found
        auto found = unverified_count.find(in_dc.prevhash());

        if (found == unverified_count.end() || (found->second + 1) >= VERIFY_SIG_PER_WRITES)
        {
            to_verify = true;
        }
        else
        {
            unverified_count[in_dc.hash()] = found->second + 1;
        }
        in_dc.set_verified(to_verify);

        // verify signature
        if (to_verify)
        {
            std::lock_guard<std::mutex> lock(storage_mutex);
            if (verify_dc(&in_dc, &this->crypto) != true)
            {
                Logger::log(LogLevel::INFO, "DataCapsule Record Verification Failed, but stored anyway. Hash: " + in_dc.hash());
            }
            else
            {
                Logger::log(LogLevel::DEBUG, "DataCapsule Record Verification Successful. Hash: " + in_dc.hash());
            }

            in_dc.set_verified(true);
            // update in_dc's count to 0
            unverified_count[in_dc.hash()] = 0;
            // mark chain of parents as verified
            std::string parent_hash = in_dc.prevhash();
            capsule::CapsulePDU parent_dc;
            while (storage.get(parent_hash, &parent_dc))
            {
                if (parent_dc.verified())
                    break;
                Logger::log(LogLevel::DEBUG, "Marking parent as verified. Parent Hash: " + parent_hash);
                parent_dc.set_verified(true);
                storage.put(&parent_dc);
                parent_hash = parent_dc.prevhash();
            }
        }
#endif
        {
            std::lock_guard<std::mutex> lock(storage_mutex);
        
            // Append the record to the chain
            bool succ = storage.put(&in_dc);
            if (!succ)
            {
                Logger::log(LogLevel::WARNING, "Append DataCapsule FAILED, skipped. Hash: "); //+ in_dc.hash());
                continue;
            }
            else
            {
                Logger::log(LogLevel::DEBUG, "Successfully appended Hash: "); // + in_dc.hash());
            }
        }

        // append signed ack to ack_q
        capsule::CapsulePDU ack_dc;
        capsule::CapsuleHeader *ack_dc_header = ack_dc.mutable_header();

        ack_dc_header->set_sender(in_dc_header->sender());
        ack_dc_header->set_msgtype(REPLICATION_ACK);
        ack_dc_header->set_replyaddr(in_dc_header->replyaddr());
        ack_dc.set_header_hash(in_dc.header_hash()); // ack_dc's header hash == in_dc's header_hash
        //ack_dc.set_hash(in_dc.hash());
#if OUTGOING_MODE == 1 or OUTGOING_MODE == 2
        sign_dc(&ack_dc, &this->crypto);
#elif OUTGOING_MODE == 3
        std::string s_digest = crypto.s_hmac_sha256(
            ack_dc.hash().c_str(), 
            ack_dc.hash().length());
        ack_dc.set_payload_hmac(s_digest);
#endif
        std::string ack_msg;
        ack_dc.SerializeToString(&ack_msg);

        // enqueue ack_msg
        this->ack_q_enqueue(ack_msg);
    }
    return 0;
}

int DC_Server::thread_handle_serve_request_msg()
{
    /*
    DC Server Handling:
    While true:
    1. get a client get request from serve_req_q
    2. Find dc using provided hash and return
    2b. if not exist, set set_record_missing to true, return empty dc
    */
    Logger::log(LogLevel::DEBUG, "thread_handle_serve_request_msg() running, dc server #" + std::to_string(this->server_id));

    while (true)
    {
        std::string in_msg = serve_req_q_dequeue();
        if (in_msg == "")
            continue;

        Logger::log(LogLevel::DEBUG, "Received a serve msg: " + in_msg);

        capsule::ClientGetRequest in_req;
        in_req.ParseFromString(in_msg);

        capsule::ClientGetResponse serve_resp;

        if (in_req.fresh_req())
        {
            // freshness read request
            Logger::log(LogLevel::DEBUG, "Received a freshness read request");

            std::unordered_set<std::string> &hashes_to_return = storage.get_sources();
            Logger::log(LogLevel::DEBUG, "Successfully fetched fresh hashes of size: " + hashes_to_return.size());
            serve_resp.set_success(true);
            serve_resp.set_targetaddr(in_req.replyaddr());
            serve_resp.set_fresh_resp(true);
            *serve_resp.mutable_fresh_hashes() = {hashes_to_return.begin(), hashes_to_return.end()};
        }
        else
        {
            // hash-based read request
            Logger::log(LogLevel::DEBUG, "Received a hash-based read request");

            std::string hash = in_req.hash();
            capsule::CapsulePDU dc_to_return;
            bool succ = storage.get(hash, &dc_to_return);

            serve_resp.set_hash(in_req.hash());
            serve_resp.set_targetaddr(in_req.replyaddr());

            if (!succ)
            {
                Logger::log(LogLevel::WARNING, "Unable to fetch DC for client. Hash: " + hash);
                serve_resp.set_success(false);
            }
            else
            {
                Logger::log(LogLevel::INFO, "Successfully fetched DC.");
                Logger::log(LogLevel::DEBUG, "Successfully fetched DC. Hash: " + hash);
                serve_resp.set_success(true);
                *serve_resp.mutable_record() = dc_to_return;
            }
        }
        
        std::string serve_resp_msg;
        serve_resp.SerializeToString(&serve_resp_msg);
        
        // enqueue serve_resp_msg
        this->serve_resp_q_enqueue(serve_resp_msg);
    }
    return 0;
}

int DC_Server::thread_send_serve_resp()
{
    Logger::log(LogLevel::DEBUG, "thread_send_serve_resp() running, dc server #" + std::to_string(this->server_id));
    comm.run_dc_server_send_serve_resp();

    return 0;
}

int DC_Server::thread_send_ack_to_replyaddr()
{
    Logger::log(LogLevel::DEBUG, "thread_send_ack_to_replyaddr() running, dc server #" + std::to_string(this->server_id));
    comm.run_dc_server_send_ack_to_replyaddr();

    return 0;
}

int DC_Server::thread_send_ack_to_leader()
{
    Logger::log(LogLevel::DEBUG, "thread_send_ack_to_leader() running, dc server #" + std::to_string(this->server_id));
    comm.run_dc_server_send_ack_to_leader();

    return 0;
}

int DC_Server::thread_send_ack_to_proxy()
{
    Logger::log(LogLevel::DEBUG, "thread_send_ack_to_proxy() running, dc server #" + std::to_string(this->server_id));
    comm.run_dc_server_send_ack_to_proxy();

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
    comm.run_leader_dc_server_handle_ack_opt1();

    return 0;
}

int DC_Server::thread_initiate_pairing()
{
    /*
        1. monitor missing records
        1a. lock storage during pairing
        2. randomly chooses another replica
        3. initiates pairing request by sending over digest
        3a. after pairing, unlock storage
    */
    Logger::log(LogLevel::INFO, "DC Server starts anti-entropy daemon: " + std::to_string(server_id));

    while (true)
    {
        // initiate pairing periodically
        std::this_thread::sleep_for(std::chrono::seconds(PAIRING_TIMEOUT_SEC));

        // lock storage
        std::lock_guard<std::mutex> lock(storage_mutex);

        // if no need to pair, continue
        if (!storage.get_record_missing())
            continue;
        Logger::log(LogLevel::INFO, "DC Server initiates pairing: " + std::to_string(server_id));

#if ANTI_ENTROPY_MODE == 1
        // get all hashes from storage
        std::unordered_set<std::string> &hashes = storage.get_all_hashes();

        // initiates pairing request by sending over all hashes
        comm.send_dc_server_pairing_request_baseline(hashes);

#elif ANTI_ENTROPY_MODE == 2
        // get digest (i.e. sources and sinks) from storage
        std::unordered_set<std::string> &sources = storage.get_sources();
        std::unordered_set<std::string> &sinks = storage.get_sinks();

        // initiates pairing request by sending over digest
        comm.send_dc_server_pairing_request(sources, sinks);
#endif
        storage.set_record_missing(false);
        // unlock storage (done by lock_guard)
    }
    return 0;
}

int DC_Server::thread_listen_pairing_msg()
{
    Logger::log(LogLevel::DEBUG, "thread_listen_pairing_msg() running, dc server #" + std::to_string(this->server_id));
    comm.run_dc_server_listen_pairing_msg();

    return 0;
}

int DC_Server::thread_handle_pairing_msg()
{
    /*
        1. receive pairing requests
        1a. lock records during pairing  (i.e. std::lock_guard<std::mutex> lock(storage_mutex);)
        2. generate a list of records to return
        3. return the list
        3a. after pairing, unlock records
    */
    while (true)
    {
        // receive pairing request (i.e. sources, sinks, and reply_addr) or response (i.e. records) from network
        std::string in_msg_s = pairing_q_dequeue();
        if (in_msg_s == "")
        {
            continue;
        }

        capsule::PairingWrapperMsg in_msg;
        in_msg.ParseFromString(in_msg_s);

        // call corresponding handler
        switch (in_msg.msg_type_case())
        {
        case capsule::PairingWrapperMsg::kRequest:
            Logger::log(LogLevel::DEBUG, "Handling a pairing request: " + in_msg_s);
            handle_pairing_request(in_msg.request());
            break;

        case capsule::PairingWrapperMsg::kResponse:
            Logger::log(LogLevel::DEBUG, "Handling a pairing response: " + in_msg_s);
            handle_pairing_response(in_msg.response());
            break;
        }
    }
    return 0;
}

void DC_Server::handle_pairing_request(const capsule::PairingRequest &req)
{
    std::vector<capsule::CapsulePDU> records_to_return;

#if ANTI_ENTROPY_MODE == 1
    // get req_hashes
    std::unordered_set<std::string> req_hashes(req.hashes().begin(), req.hashes().end());

    {
        // lock storage
        std::lock_guard<std::mutex> lock(storage_mutex);

        // use algo to generate a list of records to return
        storage.get_pairing_result_baseline(req_hashes, records_to_return);
    }

#elif ANTI_ENTROPY_MODE == 2
    // get req_sources and req_sinks
    std::unordered_set<std::string> req_sources(req.sources().begin(), req.sources().end());
    std::unordered_set<std::string> req_sinks(req.sinks().begin(), req.sinks().end());

    {
        // lock storage
        std::lock_guard<std::mutex> lock(storage_mutex);

        // use algo to generate a list of records to return
        storage.get_pairing_result(req_sources, req_sinks, records_to_return);
    }
#endif

    // return the list using Comm
    comm.send_dc_server_pairing_response(records_to_return, req.replyaddr());

    return;
}

void DC_Server::handle_pairing_response(const capsule::PairingResponse &resp)
{
    // lock storage
    std::lock_guard<std::mutex> lock(storage_mutex);

    // verify and store records
    for (const capsule::CapsulePDU &in_dc : resp.records())
    {
        bool succ = verify_dc(&in_dc, &this->crypto);
        if (succ != true)
        {
            Logger::log(LogLevel::INFO, "[DC Pairing] Paired DC Record Verification Failed, but stored anyway. Hash: "); //+ in_dc.hash());
        }
        else
        {
            Logger::log(LogLevel::DEBUG, "[DC Pairing] Paired DC Record Verification Successful. Hash: "); // + in_dc.hash());
        }

        succ = storage.put(&in_dc);
        if (!succ)
        {
            Logger::log(LogLevel::WARNING, "[DC Pairing] Append Paired DC FAILED. Hash: "); //+ in_dc.hash());
        }
        else
        {
            Logger::log(LogLevel::DEBUG, "[DC Pairing] Successfully appended Paired DC Hash:"); // " + in_dc.hash());
        }
    }

    // no longer need to repair for now
    storage.set_record_missing(false);
    Logger::log(LogLevel::INFO, "[DC Pairing] After pairing sources.size(): " +
                                     std::to_string(storage.get_sources().size()) +
                                     " sinks.size(): " + std::to_string(storage.get_sinks().size()) +
                                     " all_hashes.size(): " + std::to_string(storage.get_all_hashes().size()));

    return;
}

void DC_Server::mcast_q_enqueue(const std::string &mcast_msg)
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

void DC_Server::serve_req_q_enqueue(const std::string &serve_msg)
{
    std::lock_guard<std::mutex> lock_guard(this->serve_req_q_mutex);
    this->serve_req_q.push(serve_msg);
}

std::string DC_Server::serve_req_q_dequeue()
{
    std::lock_guard<std::mutex> lock_guard(this->serve_req_q_mutex);
    std::string in_msg = "";
    if (!this->serve_req_q.empty())
    {
        in_msg = this->serve_req_q.front();
        this->serve_req_q.pop();
    }
    return in_msg;
}

void DC_Server::serve_resp_q_enqueue(const std::string &serve_msg)
{
    std::lock_guard<std::mutex> lock_guard(this->serve_resp_q_mutex);
    this->serve_resp_q.push(serve_msg);
}

std::string DC_Server::serve_resp_q_dequeue()
{
    std::lock_guard<std::mutex> lock_guard(this->serve_resp_q_mutex);
    std::string in_msg = "";
    if (!this->serve_resp_q.empty())
    {
        in_msg = this->serve_resp_q.front();
        this->serve_resp_q.pop();
    }
    return in_msg;
}

void DC_Server::ack_q_enqueue(const std::string &ack_msg)
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

void DC_Server::pairing_q_enqueue(const std::string &pairing_msg)
{
    std::lock_guard<std::mutex> lock_guard(this->pairing_q_mutex);
    this->pairing_q.push(pairing_msg);
}

std::string DC_Server::pairing_q_dequeue()
{
    std::lock_guard<std::mutex> lock_guard(this->pairing_q_mutex);
    std::string in_msg = "";
    if (!this->pairing_q.empty())
    {
        in_msg = this->pairing_q.front();
        this->pairing_q.pop();
    }
    return in_msg;
}
