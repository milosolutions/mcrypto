#pragma once

#include "mcrypto.h"
#include "qaesencryption.h"

class MCB_QAes : public MCrypto::Backend
{
public:
    MCB_QAes(MCrypto::KEY_SIZE bits, MCrypto::MODE mode);
    QByteArray encrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt) final;
    QByteArray decrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt) final;
private:
    static QAESEncryption::AES aesToQAesEnc(const MCrypto::KEY_SIZE bits);
    static QAESEncryption::MODE modeToQAesMode(const MCrypto::MODE mode);
    QAESEncryption::AES m_encryption;
    QAESEncryption::MODE m_encryptionMode;
};

