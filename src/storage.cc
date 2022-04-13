#include <numeric>
#include <queue>
#include <string>
#include <unordered_set>
#include <vector>

#include "capsule.pb.h"
#include "config.h"
#include "rocksdb/db.h"
#include "storage.hpp"
#include "util/logging.hpp"

Storage::Storage(const std::string& db_path)
{
    rocksdb::Options options;
    options.create_if_missing = true;

    if (INITIATE_EMPTY_DB)
    {
        DestroyDB(db_path, options);
    }
    
    rocksdb::Status status =
        rocksdb::DB::Open(options, db_path, &db);
    if (status.ok())
    {
        Logger::log(LogLevel::INFO, "[Storage Init] Done, path: " + db_path);
    }
    else
    {
        Logger::log(LogLevel::ERROR, "[Storage Init] FAILED, path: " + db_path);
    }

    // Initialize sources, sinks, and reverse_map
    rocksdb::Iterator *it = db->NewIterator(rocksdb::ReadOptions());
    capsule::CapsulePDU dc;
    std::string serialized_dc;
    for (it->SeekToFirst(); it->Valid(); it->Next())
    {
        serialized_dc = it->value().ToString();
        dc.ParseFromString(serialized_dc);

        // construct internal state (i.e. reverse_map, sources, sinks)
        update_internal_state(dc.hash(), dc.prevhash(), /* update_record_missing */ false);
    }
    delete it;

    // need to initiate pairing request after initializing
    set_record_missing(true);
}

bool Storage::put(const capsule::CapsulePDU *dc)
{
    // store in rocksdb
    std::string serialized_dc;
    dc->SerializeToString(&serialized_dc);

    rocksdb::Status status =
        db->Put(rocksdb::WriteOptions(), dc->hash(), serialized_dc);

    if (!status.ok())
    {
        Logger::log(LogLevel::ERROR, "[Put] Put in DB FAILED, hash: " + dc->hash() + " value: " + serialized_dc);
        return false;
    }

    Logger::log(LogLevel::DEBUG, "[Put] Put in DB Done, hash: " + dc->hash() + " value: " + serialized_dc);

    // update reverse_map, sources, sinks, record_missing
    update_internal_state(dc->hash(), dc->prevhash());
    Logger::log(LogLevel::DEBUG, "[Put] state updated, hash: " + dc->hash());

    return true;
}

bool Storage::update_internal_state(const std::string &hash,
                                    const std::string &prevhash,
                                    const bool update_record_missing)
{
    /* update reverse_map */
    reverse_map.emplace(prevhash, hash);
    Logger::log(LogLevel::DEBUG, "<prevhash,hash> added to reverse_map: " + prevhash + " " + hash);

    /* update sources */
    // add dc itself if it is not a parent
    auto it_m = reverse_map.find(hash);
    if (it_m == reverse_map.end())
    {
        sources.insert(hash);
        Logger::log(LogLevel::DEBUG, "Hash added to sources: " + hash);
    }

    // remove dc's parent
    auto it_s = sources.find(prevhash);
    if (it_s != sources.end()) {
        sources.erase(it_s);
        Logger::log(LogLevel::DEBUG, "Hash removed from sources: " + prevhash);
    }    

    /* update sinks */
    // remove records whose prevhash is hash
    auto it_range = reverse_map.equal_range(hash);
    for (auto it = it_range.first; it != it_range.second; ++it) {
        sinks.erase(it->second);
        Logger::log(LogLevel::DEBUG, "Hash removed from sinks: " + it->second);
    }

    // add if dc is a sink
    std::string unused_serialized_dc;
    rocksdb::Status status = db->Get(
        rocksdb::ReadOptions(), prevhash, &unused_serialized_dc);
    if (!status.ok() || status.IsNotFound())
    {
        // no parent, add dc to sinks
        Logger::log(LogLevel::DEBUG, "Hash added to sinks: " + hash);
        sinks.insert(hash);
        /* update record missing */
        if (update_record_missing && prevhash != "init") 
        {
            Logger::log(LogLevel::DEBUG, "Record missing: " + prevhash);
            set_record_missing(true);
        }
    }
   
    return true;
}

bool Storage::get(const std::string& key, capsule::CapsulePDU* dc) {
    std::string serialized_dc;

    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), key, &serialized_dc);

    if (status.ok() && !status.IsNotFound()) {
        Logger::log(LogLevel::DEBUG, "[Get] Done, key: " + key + " value: " + serialized_dc);
        dc->ParseFromString(serialized_dc);
        return true;
    }
    else if (status.IsNotFound())
    {
        Logger::log(LogLevel::DEBUG, "[Get] Key does not exist: " + key);
        if (key != "init")
        {
            Logger::log(LogLevel::DEBUG, "Record missing: " + dc->prevhash());
            set_record_missing(true);
        }
        return false;
    }
    else 
    {
        Logger::log(LogLevel::ERROR, "[Get] FAILED, key: " + key);
        return false;
    }    
}

void Storage::get_pairing_result(
    std::unordered_set<std::string> &req_sources,
    std::unordered_set<std::string> &req_sinks,
    std::vector<capsule::CapsulePDU> &records_to_return) 
{
    std::unordered_set<std::string> records_to_return_hash;
    /*
        A <- B <- C
               ^\ D
        E
        definition of ahead: B, C, D are ahead of A; C, D are ahead of B 
        definition of after: A is after B, C, D; A, B are after C, D
        definition of connected: A, B, C, D are connected to each other; E is not connected to any
    */
    
    /*
    for v ∈ sourceA do
        if v ∈ nodeB and v ∉ sourceB then add all connected nodes ahead of v in nodeB to L, 
            until we reach a node in sinkA or in L
    */
    std::queue<std::string> add_ahead_q;

    for (auto &src_s: req_sources)
    {
        if (sources.find(src_s) != sources.end()) continue;
        add_ahead_q.emplace(src_s);
        Logger::log(LogLevel::DEBUG, "add_ahead_q.emplace(src_s): " + src_s);
    }

    add_records_ahead(add_ahead_q, req_sources, req_sinks, records_to_return, records_to_return_hash);
    
    Logger::log(LogLevel::DEBUG, "after add ahead of sources - records_to_return hashs: " +
                                     std::accumulate(std::begin(records_to_return_hash),
                                                     std::end(records_to_return_hash),
                                                     std::string{},
                                                     [](const std::string &a, const std::string &b)
                                                     { return a.empty() ? b
                                                                        : a + ',' + b; }));

    /* 
    for v ∈ sinkA do 
        if v ∈ nodeB and v ∉ sinkB then add all connected nodes after v in nodeB to L, until we reach a node in sourceA or in L
    */
    std::queue<std::string> add_after_q;

    for (auto &sk_s: req_sinks)
    {
        if (sinks.find(sk_s) != sinks.end()) continue;
        add_after_q.emplace(sk_s);
        Logger::log(LogLevel::DEBUG, "add_after_q.emplace(sk_s): " + sk_s);
    }

    add_records_after(add_after_q, req_sources, req_sinks, records_to_return, records_to_return_hash);
    Logger::log(LogLevel::DEBUG, "after add after sinks - records_to_return hashs: " +
                                     std::accumulate(std::begin(records_to_return_hash),
                                                     std::end(records_to_return_hash),
                                                     std::string{},
                                                     [](const std::string &a, const std::string &b)
                                                     { return a.empty() ? b
                                                                        : a + ',' + b; }));

    /* 
    for v ∈ sourceB do
        if v ∉ sourceA and v ∉ L then add connected component of v to L
    for v ∈ sinkB do
        if v ∉ sinkA and v ∉ L then add connected component of v to L
    */
    /* Do not add connected parts if your record is missing
        o/w additional sinks or sources can generate a large amount of unnecessary records
    */
    if (get_record_missing()) return; 

    std::queue<std::string> add_connected_q;

    for (auto &m_src_s: sources)
    {
        if (req_sources.find(m_src_s) != req_sources.end() ||
            records_to_return_hash.find(m_src_s) != records_to_return_hash.end())
            continue;
        
        add_connected_q.emplace(m_src_s);
    }
    for (auto &m_sk_s: sinks)
    {
        if (req_sinks.find(m_sk_s) != req_sinks.end() ||
            records_to_return_hash.find(m_sk_s) != records_to_return_hash.end())
            continue;
        
        add_connected_q.emplace(m_sk_s);
    }

    // Add records ahead
    std::queue<std::string> add_connected_q_copy = add_connected_q;
    add_records_ahead(add_connected_q_copy, req_sources, req_sinks, records_to_return, records_to_return_hash);

    // Add records after
    add_records_after(add_connected_q, req_sources, req_sinks, records_to_return, records_to_return_hash);

    Logger::log(LogLevel::DEBUG, "after add connected - records_to_return hashs: " +
                                     std::accumulate(std::begin(records_to_return_hash),
                                                     std::end(records_to_return_hash),
                                                     std::string{},
                                                     [](const std::string &a, const std::string &b)
                                                     { return a.empty() ? b
                                                                        : a + ',' + b; }));

    return;
}

void Storage::add_records_ahead(
    std::queue<std::string> &ahead_q,
    std::unordered_set<std::string> &req_sources,
    std::unordered_set<std::string> &req_sinks,
    std::vector<capsule::CapsulePDU> &records_to_return,
    std::unordered_set<std::string> &records_to_return_hash)
{
    std::string next_dc_serialized;
    capsule::CapsulePDU next_dc;
    while (ahead_q.size() > 0)
    {
        std::string next = ahead_q.front();
        ahead_q.pop();
        
        if (req_sinks.find(next) != req_sinks.end() || 
            records_to_return_hash.find(next) != records_to_return_hash.end()) 
                continue;
        
        rocksdb::Status status = db->Get(
            rocksdb::ReadOptions(), next, &next_dc_serialized);
        if (!status.ok() || status.IsNotFound())
        {
            Logger::log(LogLevel::DEBUG, "Record missing: " + next);
            set_record_missing(true);
            continue;
        }
        next_dc.ParseFromString(next_dc_serialized);

        // found a new record, add to return list if not in req_sources
        if (req_sources.find(next) == req_sources.end())
        {
            records_to_return.emplace_back(next_dc);
            records_to_return_hash.insert(next);
        }

        // add next's children
        auto it_range = reverse_map.equal_range(next);
        for (auto it = it_range.first; it != it_range.second; ++it) {
            ahead_q.emplace(it->second);
        }
    }
}

void Storage::add_records_after(
    std::queue<std::string> &after_q,
    std::unordered_set<std::string> &req_sources,
    std::unordered_set<std::string> &req_sinks,
    std::vector<capsule::CapsulePDU> &records_to_return,
    std::unordered_set<std::string> &records_to_return_hash)
{
    std::string next_dc_serialized;
    capsule::CapsulePDU next_dc;
    while (after_q.size() > 0)
    {
        std::string next = after_q.front();
        after_q.pop();

        if (req_sources.find(next) != req_sources.end() || 
            records_to_return_hash.find(next) != records_to_return_hash.end())
                continue;

        rocksdb::Status status = db->Get(
            rocksdb::ReadOptions(), next, &next_dc_serialized);
        if (!status.ok() || status.IsNotFound())
        {
            Logger::log(LogLevel::DEBUG, "Record missing: " + next);
            set_record_missing(true);
            continue;
        }
        next_dc.ParseFromString(next_dc_serialized);

        // found a new record, add to return list if not in req_sinks
        if (req_sinks.find(next) == req_sinks.end())
        {
            records_to_return.emplace_back(next_dc);
            records_to_return_hash.insert(next);
        }

        // add next's parent
        after_q.emplace(next_dc.prevhash());
    }
}

std::unordered_set<std::string> &Storage::get_sources() 
{
    return sources;
}

std::unordered_set<std::string> &Storage::get_sinks() 
{
    return sinks;
}

bool Storage::get_record_missing() 
{
    return record_missing;
}

void Storage::set_record_missing(bool val)
{
    record_missing = val;
    return;
}
