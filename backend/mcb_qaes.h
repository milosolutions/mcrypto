#pragma once

#include "mcrypto.h"
#include "qaesencryption.h"

class MCB_QAes : public MCrypto::Backend
{
public:
    MCB_QAes(MCrypto::AES encryption, MCrypto::MODE mode);
    QByteArray encrypt(const QByteArray &inba, const QByteArray &pwd) final;
    QByteArray decrypt(const QByteArray &inba, const QByteArray &pwd) final;
private:
    static QAESEncryption::AES aesToQAesEnc(const MCrypto::AES level);
    static QAESEncryption::MODE modeToQAesMode(const MCrypto::MODE level);
    QAESEncryption::AES m_encryption;
    QAESEncryption::MODE m_encryptionMode;
};

