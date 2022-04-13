#ifndef __UTILS_H
#define __UTILS_H

#include <cmath>
#include <functional>
#include <string>
namespace Utils
{

    int hashToInt(const std::string &hash_s, const int total_num)
    {
        std::hash<std::string> hasher;
        int hashed = std::abs((int)hasher(hash_s));
        return hashed % total_num;
    }

};

#endif // __UTILS_H