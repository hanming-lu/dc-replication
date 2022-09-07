#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <openssl/evp.h>
#include <string>

class Crypto
{
public:
    Crypto();
    ~Crypto();

    std::string sign_message(const std::string &msg);
    bool verify_message(const std::string &msg, const std::string &signature_s);

    std::string encrypt_message(const std::string &msg);
    std::string decrypt_message(const std::string &enc_msg, const size_t orig_msg_len);

private:
    /* for sign */
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md = NULL;

    /* for encryption */
    std::string encrypt_key = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567";
    size_t AES_KEYLENGTH = 128;
    unsigned char aes_key[128];
    
};

#endif // __CRYPTO_H