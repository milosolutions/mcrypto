#include "mcrypto.h"
#include "qaesencryption.h"
#include <QCryptographicHash>

// Convert Crypto::AES to QAESEncryption::AES
QAESEncryption::AES aesToQAesEnc(const MCrypto::AES_TYPE algo)
{
    switch(algo)
    {
        case MCrypto::AES_128:
            return QAESEncryption::AES_128;
        case MCrypto::AES_192:
            return QAESEncryption::AES_192;
        case MCrypto::AES_256:
            return QAESEncryption::AES_256;
    }
    Q_UNREACHABLE();
}

// Convert Crypto::MODE to QAESEncryption::MODE
QAESEncryption::MODE modeToQAesMode(const MCrypto::MODE mode)
{
    switch(mode)
    {
        case MCrypto::CBC:
            return QAESEncryption::CBC;
        case MCrypto::CFB:
            return QAESEncryption::CFB;
        case MCrypto::ECB:
            return QAESEncryption::ECB;
    }
    Q_UNREACHABLE();
}

struct MCrypto::InternalData
{
    QAESEncryption::AES keysize;
    QAESEncryption::MODE mode;
};

MCrypto::Backend::Backend(MCrypto::KEY_SIZE bits, MCrypto::MODE mode)
{
    m = new InternalData;
    m->keysize = aesToQAesEnc(bits);
    m->mode = modeToQAesMode(mode);
}

MCrypto::Backend::~Backend()
{
    delete m;
}

QByteArray MCrypto::Backend::encrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    QByteArray hashKey = QCryptographicHash::hash(pwd, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(salt, QCryptographicHash::Md5);

    return QAESEncryption::Crypt(m->keysize, m->mode, input, hashKey, hashIV);
}

QByteArray MCrypto::Backend::decrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    QByteArray hashKey = QCryptographicHash::hash(pwd, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(salt, QCryptographicHash::Md5);

    // converted to QString because QAesEncryption added nullptr bytes at the end
    return QString(QAESEncryption::Decrypt(m->keysize, m->mode, input, hashKey, hashIV)).toLocal8Bit();
}
MCrypto::Backend::Backend(MCrypto::AES_TYPE bits, MCrypto::MODE mode)
