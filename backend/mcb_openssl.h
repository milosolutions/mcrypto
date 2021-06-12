#pragma once

#include "mcrypto.h"

struct evp_cipher_ctx_st;
using EVP_CIPHER_CTX = evp_cipher_ctx_st;

class MCB_OpenSsl : public MCrypto::Backend
{
public:
    MCB_OpenSsl(MCrypto::KEY_SIZE bits, MCrypto::MODE mode);
    QByteArray encrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt) final;
    QByteArray decrypt(const QByteArray &inba, const QByteArray &pwd, const QByteArray &salt) final;
private:
    bool initEnc(const QByteArray &pwd);
    bool initDec(const QByteArray &pwd);
    EVP_CIPHER_CTX *e_ctx = nullptr;
    EVP_CIPHER_CTX *d_ctx = nullptr;
    QByteArray m_key;
    QByteArray m_iv;
    QByteArray m_algorithm;
    const QByteArray m_salt;
};

