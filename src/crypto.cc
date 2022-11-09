#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/sha.h>
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

    Logger::log(LogLevel::DEBUG, "[Crypto] PKey Generation Successful");

    // Initiate MD CTX for sign and verify
    if (!(this->md_sign = EVP_MD_CTX_create()))
    {
        Logger::log(LogLevel::ERROR, "[Crypto] MDCTX Create ERROR");
        throw;
    }

    if (!(this->md_verify = EVP_MD_CTX_create()))
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
    EVP_MD_CTX_destroy(this->md_sign);
    EVP_MD_CTX_destroy(this->md_verify);
}

std::string Crypto::sign_message(const std::string &msg)
{   
    EVP_MD_CTX_reset(this->md_sign);
    if (EVP_DigestSignInit(this->md_sign, NULL, EVP_sha256(), NULL, this->pkey) != 1)
    {
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR 1");
        throw;
    }

    if (EVP_DigestSignUpdate(this->md_sign, msg.data(), msg.size()) != 1)
    {
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR 2");
        throw;
    }
    size_t s_len;
    if (EVP_DigestSignFinal(this->md_sign, NULL, &s_len) != 1)
    { // Segfault here
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR 3, error code: " + (std::string) ERR_reason_error_string(ERR_get_error()) +
            ", s_len: " + std::to_string(s_len) + 
            ", msg.size(): " + std::to_string(msg.size()) + 
            ", msg.data(): " + msg.data());
        throw;
    }

    std::vector<unsigned char> signature(s_len);
    if (EVP_DigestSignFinal(this->md_sign, signature.data(), &s_len) != 1)
    { // or here (or both)
        Logger::log(LogLevel::ERROR, "[Crypto] Sign ERROR 4, error code: " + (std::string) ERR_reason_error_string(ERR_get_error()) +
            ", s_len: " + std::to_string(s_len) + 
            ", msg.size(): " + std::to_string(msg.size()) + 
            ", msg.data(): " + msg.data());
        throw;
    }
    signature.resize(s_len);
    std::string signature_s(signature.begin(), signature.end());

    return signature_s;
}

bool Crypto::verify_message(const std::string &msg, const std::string &signature_s)
{
    std::vector<unsigned char> signature(signature_s.begin(), signature_s.end());

    if (1 != EVP_DigestVerifyInit(this->md_verify, NULL, EVP_sha256(), NULL, this->pkey))
    {
        Logger::log(LogLevel::ERROR, "[Crypto] Verify ERROR");
        throw;
    }

    if (1 != EVP_DigestVerifyUpdate(this->md_verify, msg.data(), msg.size()))
    {
        Logger::log(LogLevel::ERROR, "[Crypto] Verify ERROR");
        throw;
    }

    if (1 == EVP_DigestVerifyFinal(this->md_verify, signature.data(), signature.size()))
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

std::string Crypto::b2a_hex(const std::uint8_t *p, std::size_t n)
{
    static const char hex[] = "0123456789abcdef";
    std::string res;
    res.reserve(n * 2);

    for (auto end = p + n; p != end; ++p)
    {
        const std::uint8_t v = (*p);
        res += hex[(v >> 4) & 0x0F];
        res += hex[v & 0x0F];
    }

    return res;
}

std::string Crypto::c_hmac_sha256(
    const char *data, unsigned int dlen)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dilen;
    ::HMAC(
        ::EVP_sha256(), c_hmac_key, c_klen, (unsigned char *)data, dlen, digest, &dilen);

    return b2a_hex(digest, dilen);
}

std::string Crypto::s_hmac_sha256(
    const char *data, unsigned int dlen)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dilen;
    ::HMAC(
        ::EVP_sha256(), s_hmac_key, s_klen, (unsigned char *)data, dlen, digest, &dilen);

    return b2a_hex(digest, dilen);
}

std::string Crypto::bin_sha256(
    const char *data, unsigned int dlen)
{
    unsigned char hash_buf[SHA256_DIGEST_LENGTH];
    std::string emp_str("");
    SHA256_CTX hsh_ctx;
    if (!SHA256_Init(&hsh_ctx)){
        return emp_str;         // Fail silently
    }
    if (!SHA256_Update(&hsh_ctx, (void *)data, dlen)){
        return emp_str;
    }
    if (!SHA256_Final(hash_buf, &hsh_ctx)){
        return emp_str;
    }

    return std::string((char *)hash_buf, SHA256_DIGEST_LENGTH); // use string as container for binary format
}