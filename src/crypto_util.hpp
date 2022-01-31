#ifndef __CRYPTOUTIL_H
#define __CRYPTOUTIL_H

#include "capsule.pb.h"
#include "crypto.hpp"

bool sign_dc(capsule::CapsulePDU *dc, Crypto *crypto);

bool verify_dc(const capsule::CapsulePDU *dc, Crypto *crypto); 

#endif // __CRYPTOUTIL_H