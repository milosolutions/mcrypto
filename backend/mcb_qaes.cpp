#include "mcb_qaes.h"
#include <QCryptographicHash>

MCB_QAes::MCB_QAes(MCrypto::AES encryption, MCrypto::MODE mode)
: m_encryption(aesToQAesEnc(encryption)), m_encryptionMode(modeToQAesMode(mode))
{
    // Nothing
}

QByteArray MCB_QAes::encrypt(const QByteArray &inba, const QByteArray &pwd)
{
    QByteArray hashKey = QCryptographicHash::hash(pwd, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(QByteArray(), QCryptographicHash::Md5);

    return QAESEncryption::Crypt(m_encryption, m_encryptionMode, inba, hashKey, hashIV);
}

QByteArray MCB_QAes::decrypt(const QByteArray &inba, const QByteArray &pwd)
{
    QByteArray hashKey = QCryptographicHash::hash(pwd, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(QByteArray(), QCryptographicHash::Md5);

    // converted to QString because QAesEncryption added nullptr bytes at the end
    return QString(QAESEncryption::Decrypt(m_encryption, m_encryptionMode, inba, hashKey, hashIV)).toLocal8Bit();
}

/*!
 * \brief Convert Crypto::AES to QAESEncryption::AES
 * \param level
 * \return Converted aes enum
 */
QAESEncryption::AES MCB_QAes::aesToQAesEnc(const MCrypto::AES level)
{
    switch(level)
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
