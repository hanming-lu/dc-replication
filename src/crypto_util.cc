#include <string>

#include "crypto_util.hpp"
#include "crypto.hpp"

bool sign_dc(capsule::CapsulePDU *dc, Crypto *crypto)
{
    std::string aggregated = dc->hash() + dc->prevhash();
    dc->set_signature(crypto->sign_message(aggregated));
    return true;
}

bool verify_dc(const capsule::CapsulePDU *dc, Crypto *crypto)
{
    std::string aggregated = dc->hash() + dc->prevhash();
    bool res = crypto->verify_message(aggregated, dc->signature());
    return true;
}