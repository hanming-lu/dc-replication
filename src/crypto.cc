#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/aes.h>
#include <cstring>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "util/logging.hpp"

Crypto::Crypto()
{
    /* for sign */
    // Initiate pkey
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL)
    {
        Logger::log(LogLevel::ERROR, "[Crypto] PKey Generation ERROR");
        throw;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        Logger::log(LogLevel::ERROR, "[Crypto] PKey Generation ERROR");
        throw;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
    {
        Logger::log(LogLevel::ERROR, "[Crypto] PKey Generation ERROR");
        throw;
    }

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &this->pkey) <= 0)
    {
        Logger::log(LogLevel::ERROR, "[Crypto] PKey Generation ERROR");
        throw;
    }

    Logger::log(LogLevel::INFO, "[Crypto] PKey Generation Successful");

    // Initiate MD CTX
    if (!(this->md = EVP_MD_CTX_create()))
    {
        Logger::log(LogLevel::ERROR, "[Crypto] MDCTX Create ERROR");
        throw;
    }

    Logger::log(LogLevel::INFO, "[Crypto] MDCTX Create Successful");

    /* for encrypt */
    memset(aes_key, 0, AES_KEYLENGTH/8);
    strcpy((char*) aes_key, encrypt_key.c_str());
}

Crypto::~Crypto()
{
    EVP_PKEY_free(this->pkey);
    EVP_MD_CTX_destroy(this->md);
}

std::string Crypto::sign_message(const std::string &msg)
{
    if (EVP_DigestSignInit(this->md, NULL, EVP_sha256(), NULL, this->pkey) != 1)
    {
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR");
        throw;
    }

    if (EVP_DigestSignUpdate(this->md, msg.data(), msg.size()) != 1)
    {
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR");
        throw;
    }
    size_t s_len;
    if (EVP_DigestSignFinal(this->md, NULL, &s_len) != 1)
    { // Segfault here
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR");
        throw;
    }

    std::vector<unsigned char> signature(s_len);
    if (EVP_DigestSignFinal(this->md, signature.data(), &s_len) != 1)
    { // or here (or both)
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR");
        throw;
    }
    signature.resize(s_len);
    std::string signature_s(signature.begin(), signature.end());

    return signature_s;
}

bool Crypto::verify_message(const std::string &msg, const std::string &signature_s)
{
    std::vector<unsigned char> signature(signature_s.begin(), signature_s.end());

    if (1 != EVP_DigestVerifyInit(this->md, NULL, EVP_sha256(), NULL, this->pkey))
    {
        Logger::log(LogLevel::ERROR, "[Crypto] Verify ERROR");
        throw;
    }

    if (1 != EVP_DigestVerifyUpdate(this->md, msg.data(), msg.size()))
    {
        Logger::log(LogLevel::ERROR, "[Crypto] Verify ERROR");
        throw;
    }

    if (1 == EVP_DigestVerifyFinal(this->md, signature.data(), signature.size()))
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

std::string Crypto::encrypt_message(const std::string &msg)
{
    size_t msg_len = msg.length();
    unsigned char aes_input[msg_len];
    memset(aes_input, 0, msg_len/8);
    strcpy((char*) aes_input, msg.c_str());

    /* init vector */
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    // buffers for encryption
    const size_t enc_len = ((msg_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[enc_len];
    memset(enc_out, 0, sizeof(enc_out));

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, AES_KEYLENGTH, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, msg_len, &enc_key, iv, AES_ENCRYPT);

    std::string enc_msg_s((char *)enc_out);

    return enc_msg_s;
}

std::string Crypto::decrypt_message(const std::string &enc_msg, const size_t orig_msg_len)
{
    size_t enc_msg_len = enc_msg.length();
    unsigned char aes_input[enc_msg_len];
    memset(aes_input, 0, enc_msg_len/8);
    strcpy((char*) aes_input, enc_msg.c_str());

    /* init vector */
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    // buffers for decryption
    const size_t enc_len = ((orig_msg_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char dec_out[orig_msg_len];
    memset(dec_out, 0, sizeof(dec_out));

    AES_KEY dec_key;
    AES_set_decrypt_key(aes_key, AES_KEYLENGTH, &dec_key);
    AES_cbc_encrypt(aes_input, dec_out, enc_len, &dec_key, iv, AES_DECRYPT);

    std::string dec_msg_s((char *)dec_out);

    return dec_msg_s;
}
