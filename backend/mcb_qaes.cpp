#include "mcb_qaes.h"
#include <QCryptographicHash>

MCB_QAes::MCB_QAes(MCrypto::KEY_SIZE bits, MCrypto::MODE mode)
: m_encryption(aesToQAesEnc(bits)), m_encryptionMode(modeToQAesMode(mode))
{
    // Nothing
}

QByteArray MCB_QAes::encrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    QByteArray hashKey = QCryptographicHash::hash(pwd, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(salt, QCryptographicHash::Md5);

    return QAESEncryption::Crypt(m_encryption, m_encryptionMode, input, hashKey, hashIV);
}

QByteArray MCB_QAes::decrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    QByteArray hashKey = QCryptographicHash::hash(pwd, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(salt, QCryptographicHash::Md5);

    // converted to QString because QAesEncryption added nullptr bytes at the end
    return QString(QAESEncryption::Decrypt(m_encryption, m_encryptionMode, input, hashKey, hashIV)).toLocal8Bit();
}

/*!
 * \brief Convert Crypto::AES to QAESEncryption::AES
 * \param level
 * \return Converted aes enum
 */
QAESEncryption::AES MCB_QAes::aesToQAesEnc(const MCrypto::KEY_SIZE bits)
{
    switch(bits)
    {
        case MCrypto::KEY_128:
            return QAESEncryption::AES_128;
        case MCrypto::KEY_192:
            return QAESEncryption::AES_192;
        case MCrypto::KEY_256:
            return QAESEncryption::AES_256;
    }
    Q_UNREACHABLE();
}

/*!
 * \brief Convert Crypto::MODE to QAESEncryption::MODE
 * \param mode
 * \return Converted mode enum
 */
QAESEncryption::MODE MCB_QAes::modeToQAesMode(const MCrypto::MODE mode)
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
