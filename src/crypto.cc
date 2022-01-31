#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "util/logging.hpp"

Crypto::Crypto()
{
    // Initiate pkey
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        Logger::log(LogLevel::ERROR, "[Crypto] PKey Generation ERROR");
        throw;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        Logger::log(LogLevel::ERROR, "[Crypto] PKey Generation ERROR");
        throw;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        Logger::log(LogLevel::ERROR, "[Crypto] PKey Generation ERROR");
        throw;
    }

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &this->pkey) <= 0) {
        Logger::log(LogLevel::ERROR, "[Crypto] PKey Generation ERROR");
        throw;
    }

    Logger::log(LogLevel::INFO, "[Crypto] PKey Generation Successful");

    // Initiate MD CTX
    if (!(this->md = EVP_MD_CTX_create())) {
        Logger::log(LogLevel::ERROR, "[Crypto] MDCTX Create ERROR");
        throw;
    }

    Logger::log(LogLevel::INFO, "[Crypto] MDCTX Create Successful");
}

Crypto::~Crypto(){
    EVP_PKEY_free(this->pkey);
    EVP_MD_CTX_destroy(this->md);
}

std::string Crypto::sign_message(const std::string &msg) {
    if (EVP_DigestSignInit(this->md, NULL, EVP_sha256(), NULL, this->pkey) 
            != 1) {
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR");
        throw;
    }

    if (EVP_DigestSignUpdate(this->md, msg.data(), msg.size()) != 1) {
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR");
        throw;
    }
    size_t s_len;
    if (EVP_DigestSignFinal(this->md, NULL, &s_len) != 1) { // Segfault here
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR");
        throw;
    }

    std::vector<unsigned char> signature(s_len);
    if (EVP_DigestSignFinal(this->md, signature.data(), &s_len) != 1) { // or here (or both)
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR");
        throw;
    }
    signature.resize(s_len);
    std::string signature_s(signature.begin(), signature.end());

    return signature_s;
}

bool Crypto::verify_message(const std::string &msg, const std::string &signature_s) {
    std::vector<unsigned char> signature(signature_s.begin(), signature_s.end());

    if(1 != EVP_DigestVerifyInit(this->md, NULL, EVP_sha256(), NULL, this->pkey)) {
        Logger::log(LogLevel::ERROR, "[Crypto] Verify ERROR");
        throw;
    }

    if(1 != EVP_DigestVerifyUpdate(this->md, msg.data(), msg.size())) {
        Logger::log(LogLevel::ERROR, "[Crypto] Verify ERROR");
        throw;
    }

    if(1 == EVP_DigestVerifyFinal(this->md, signature.data(), signature.size()))
    {
        /* Success */
        return true;
    }
    else
    {
        /* Failure */
        return false;
    }
}