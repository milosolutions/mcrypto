#pragma once

#include "mcrypto.h"
#include "openssl/evp.h"

class MCB_OpenSsl : public MCrypto::Backend
{
public:
    MCB_OpenSsl(MCrypto::AES encryption, MCrypto::MODE mode);
    QByteArray encrypt(const QByteArray &inba, const QByteArray &pwd) final;
    QByteArray decrypt(const QByteArray &inba, const QByteArray &pwd) final;
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

