#ifndef __CRYPTOUTIL_H
#define __CRYPTOUTIL_H

#include "capsule.pb.h"

// Todo: implement
bool sign_dc(capsule::CapsulePDU *dc, const std::string &signing_key);

// Todo: use real key's type
bool verify_dc(const capsule::CapsulePDU *dc, const std::string &verifying_key); 

#endif // __CRYPTOUTIL_H