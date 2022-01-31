#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <openssl/evp.h>
#include <string>

class Crypto {
public:
    Crypto();
    ~Crypto();

    std::string sign_message(const std::string &msg);
    bool verify_message(const std::string &msg, const std::string &signature_s);

private:
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX* md = NULL;
};

#endif // __CRYPTO_H