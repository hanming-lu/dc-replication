#ifndef __STORAGE_H
#define __STORAGE_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "capsule.pb.h"
#include "rocksdb/db.h"

class Storage {
    private:
        rocksdb::DB *db;
        std::unordered_multimap<std::string, std::string> reverse_map; // a mapping from <prevhash> to <hash>. Allow lookup by prevhash
        std::unordered_set<std::string> sources; // records without incoming links
        std::unordered_set<std::string> sinks; // records without outgoing links
        bool record_missing; // a missing record is detected or not

        // Insert Value Internal
        bool put_internal(const std::string& key, const capsule::CapsulePDU* dc);

        // Insert records ahead 
        void add_records_ahead(
            std::queue<std::string> &ahead_q,
            std::unordered_set<std::string> &req_sources,
            std::unordered_set<std::string> &req_sinks,
            std::vector<capsule::CapsulePDU> &records_to_return,
            std::unordered_set<std::string> &records_to_return_hash);

        // Insert records after
        void add_records_after(
            std::queue<std::string> &after_q,
            std::unordered_set<std::string> &req_sources,
            std::unordered_set<std::string> &req_sinks,
            std::vector<capsule::CapsulePDU> &records_to_return,
            std::unordered_set<std::string> &records_to_return_hash);

        
    public:
        // Initiate
        Storage(const std::string& db_path);

        // Insert Value
        bool put(const capsule::CapsulePDU* dc);

        // Read Value
        bool get(const std::string& key, capsule::CapsulePDU* dc);

        // Update internal state
        bool update_internal_state(const std::string &hash,
                                   const std::string &prevhash,
                                   const bool update_record_missing = true);

        // Return the set of sources
        std::unordered_set<std::string> &get_sources();

        // Return the set of sources
        std::unordered_set<std::string> &get_sinks();

        // Return pairing result
        void get_pairing_result(
            std::unordered_set<std::string> &req_sources,
            std::unordered_set<std::string> &req_sinks,
            std::vector<capsule::CapsulePDU> &records_to_return);

        // Check if pairing needed
        bool get_record_missing();
        void set_record_missing(bool val);

};

#endif // __STORAGE_H