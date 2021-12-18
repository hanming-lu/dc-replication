#ifndef __STORAGE_H
#define __STORAGE_H

#include <string>
#include "capsule.pb.h"
#include "rocksdb/db.h"

class Storage {
    private:
        rocksdb::DB *db;

    public:
        // Initiate
        Storage(const std::string& db_path);

        // Insert Value
        bool put(const std::string& key, const capsule::CapsulePDU* dc);

        // Read Value
        bool get(const std::string& key, capsule::CapsulePDU* dc);
};

#endif // __STORAGE_H