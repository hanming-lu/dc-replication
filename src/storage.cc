#include <string>

#include "capsule.pb.h"
#include "rocksdb/db.h"
#include "storage.hpp"
#include "util/logging.hpp"

Storage::Storage(const std::string& db_path)
{
    rocksdb::Options options;
    options.create_if_missing = true;
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
}

bool Storage::put(const std::string &key, const capsule::CapsulePDU *dc)
{
    std::string serialized_dc;
    dc->SerializeToString(&serialized_dc);

    rocksdb::Status status =
        db->Put(rocksdb::WriteOptions(), key, serialized_dc);

    if (status.ok())
    {
        Logger::log(LogLevel::DEBUG, "[Put] Done, key: " + key + " value: " + serialized_dc);
        return true;
    }
    else
    {
        Logger::log(LogLevel::ERROR, "[Put] FAILED, key: " + key + " value: " + serialized_dc);
        return false;
    }
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
        return false;
    }
    else 
    {
        Logger::log(LogLevel::ERROR, "[Get] FAILED, key: " + key);
        return false;
    }    
}
