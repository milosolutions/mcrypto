/*******************************************************************************
Copyright (C) 2017 Milo Solutions
Contact: https://www.milosolutions.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*******************************************************************************/

#include "mcrypto.h"

#include <QString>
#include <QUuid>
#include <QCryptographicHash>
#include <QMetaEnum>


/*!
 * \brief crypto functionality base on OpenSSL
 *  NOTICE: MacOsX uses it's own implementation that differes from OpenSSL one
 *        that's why it will generate deprecated functions warnings.
 *        To bypass this link statically OpenSSL.
 */

MCrypto::MCrypto(const MCrypto::AES encryption, const MCrypto::MODE mode)
  : encryption(aesToQAesEnc(encryption))
  , encryptionMode(modeToQAesMode(mode))
{
    // Salt mustn't be saved as plain string!
    salt = QByteArray(MCrypto::staticMetaObject.className() + QByteArray("12") + QAESEncryption::staticMetaObject.className() + QByteArray::number(0x11abc126));

#ifdef HAS_OPENSSL
    algorithm = QByteArray(QMetaEnum::fromType<MCrypto::AES>().valueToKey(int(encryption))).replace('_', '-') + QByteArray("-") + QByteArray(QMetaEnum::fromType<MCrypto::MODE>().valueToKey(int(mode)));
#endif
}


/*!
 * \brief Static method to encrypt data
 * \param level
 * \param mode
 * \param encryptedText
 * \param key
 * \param iv default empty string
 * \return Encrypted data
 */

QByteArray MCrypto::encrypt(const MCrypto::AES level, const MCrypto::MODE mode, const QByteArray &rawText, const QByteArray &key, const QByteArray &iv)
{
#ifdef HAS_OPENSSL
//    qDebug() << "using OpenSSL |" << Q_FUNC_INFO;
    Q_UNUSED(iv);
    return MCrypto(level, mode).encrypt(rawText, key);

#else

//    qDebug() << "using Qt-AES |" << Q_FUNC_INFO;
    QByteArray hashKey = QCryptographicHash::hash(key, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(iv, QCryptographicHash::Md5);

    return QAESEncryption::Crypt(MCrypto::aesToQAesEnc(level), modeToQAesMode(mode), rawText, hashKey, hashIV);

#endif
}

/*!
 * \brief Static method to decrypt data
 * \param level
 * \param mode
 * \param encryptedText
 * \param key
 * \param iv default empty string
 * \return Decrypted data
 */
QByteArray MCrypto::decrypt(const MCrypto::AES level, const MCrypto::MODE mode, const QByteArray &encryptedText, const QByteArray &key, const QByteArray &iv)
{
#ifdef HAS_OPENSSL
//    qDebug() << "using OpenSSL |" << Q_FUNC_INFO;
    Q_UNUSED(iv);
    return MCrypto(level, mode).decrypt(encryptedText, key);

#else

//    qDebug() << "using Qt-AES |" << Q_FUNC_INFO;
    QByteArray hashKey = QCryptographicHash::hash(key, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(iv, QCryptographicHash::Md5);

    // converted to QString because QAesEncryption added null bytes at the end
    return QString(QAESEncryption::Decrypt(MCrypto::aesToQAesEnc(level), modeToQAesMode(mode), encryptedText, hashKey, hashIV)).toLocal8Bit();

#endif
}

/*!
 * \brief Convert Crypto::AES to QAESEncryption::AES
 * \param level
 * \return Converted aes enum
 */
QAESEncryption::AES MCrypto::aesToQAesEnc(const MCrypto::AES level)
{
  switch(level)
  {
    case MCrypto::AES_128:
      return QAESEncryption::AES_128;
    case MCrypto::AES_192:
      return QAESEncryption::AES_192;
    default:
    case MCrypto::AES_256:
      return QAESEncryption::AES_256;
  }
}

/*!
 * \brief Convert Crypto::MODE to QAESEncryption::MODE
 * \param mode
 * \return Converted mode enum
 */

QAESEncryption::MODE MCrypto::modeToQAesMode(const MCrypto::MODE mode)
{
  switch(mode)
  {
    default:
    case MCrypto::CBC:
      return QAESEncryption::CBC;
    case MCrypto::CFB:
      return QAESEncryption::CFB;
    case MCrypto::ECB:
      return QAESEncryption::ECB;
  }
}

/*!
 * \brief init encryption algorithm
 * \param pwd if empty content is NOT encrypted
 * \return true on success
 */

bool MCrypto::initEnc(const QByteArray &pwd)
{
#ifdef HAS_OPENSSL
    key.clear();
    iv.clear();
    key.resize(EVP_MAX_KEY_LENGTH);
    iv.resize(EVP_MAX_IV_LENGTH);

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    EVP_CIPHER_CTX_init(&e_ctx);

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(qPrintable(algorithm));
    if (!cipher) {
        EVP_CIPHER_CTX_cleanup(&e_ctx);
        EVP_cleanup();
        return false;
    }

    const EVP_MD *dgst = EVP_get_digestbyname(qPrintable("md5"));

    if (!dgst) {
        EVP_CIPHER_CTX_cleanup(&e_ctx);
        EVP_cleanup();
        return false;
    }

    if(!EVP_BytesToKey(cipher, dgst, (const unsigned char *) salt.constData(),
                       (const unsigned char *) pwd.constData(), pwd.size(),
                       1, (unsigned char *)key.data(), (unsigned char *)iv.data()))
     {
         return false;
     }

    if (key.isEmpty() || iv.isEmpty())
        return false;

    if (!EVP_EncryptInit_ex(&e_ctx, cipher, NULL,
                            (const unsigned char*)key.constData(),
                            (const unsigned char*)iv.constData()))
        return false;

    return true;

#else
    Q_UNUSED (pwd)
    return false;
#endif
}

/*!
 * \brief encrypt data from \param inba until \param pwd
 * \return encrypted data
 *      NOTE: inba don't need to contains wholed data that is
 *      encrypted to operate corectly it can be small chunk of
 *      i.e. whole file
 */

QByteArray MCrypto::encrypt(const QByteArray &inba, const QByteArray &pwd)
{
    QByteArray outbuf;

#ifdef HAS_OPENSSL
    if (initEnc(pwd))
    {
        int inlen = 0, outlen = 0;
            inlen = inba.size();

        outbuf = QByteArray(inlen + EVP_MAX_BLOCK_LENGTH, 0);

        if (!EVP_EncryptUpdate(&e_ctx, (unsigned char*)outbuf.data(), &outlen,
                               (const unsigned char*)inba.constData(), inlen)) {
            return QByteArray();
        }

        int tmplen = 0;

        if (!EVP_EncryptFinal_ex(&e_ctx,
                                 ((unsigned char*)outbuf.data()) + outlen, &tmplen)) {
            return QByteArray();
        }

        outlen += tmplen;

        EVP_CIPHER_CTX_cleanup(&e_ctx);
        EVP_cleanup();
        outbuf.resize(outlen);
    }
    else
      qCritical() << "Unable to init encode crypt!";
#else
    QByteArray hashKey = QCryptographicHash::hash(pwd, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(QByteArray(), QCryptographicHash::Md5);

    return QAESEncryption::Crypt(encryption, encryptionMode, inba, hashKey, hashIV);
#endif

    return outbuf;
}

/*!
 * \brief initialise decoder to use
 * \param pwd
 * \return initialization status
 */

bool MCrypto::initDec(const QByteArray &pwd)
{
#ifdef HAS_OPENSSL
    key.clear();
    iv.clear();

    key.resize(EVP_MAX_KEY_LENGTH);
    iv.resize(EVP_MAX_IV_LENGTH);

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    EVP_CIPHER_CTX_init(&d_ctx);

    const EVP_CIPHER *decipher = EVP_get_cipherbyname(qPrintable(algorithm));
    if (!decipher) {
        EVP_CIPHER_CTX_cleanup(&d_ctx);
        EVP_cleanup();
        return false;
    }

    const EVP_MD *dgst = EVP_get_digestbyname(qPrintable("md5"));

    if (!dgst) {
        EVP_CIPHER_CTX_cleanup(&d_ctx);
        EVP_cleanup();
        return false;
    }

    if(!EVP_BytesToKey(decipher, dgst, (const unsigned char *) salt.constData(),
                       (const unsigned char *) pwd.constData(), pwd.size(),
                       1, (unsigned char *)key.data(), (unsigned char *)iv.data()))
     {
         return false;
     }

    if (key.isEmpty() || iv.isEmpty())
        return false;

    if (!EVP_DecryptInit_ex(&d_ctx, decipher, NULL,
                            (const unsigned char*)key.constData(),
                            (const unsigned char*)iv.constData()))
        return false;

    return true;
#else
    Q_UNUSED (pwd)
    return false;
#endif
}

/*!
 * \brief decrypt data in \param inba until end \param pwd
 * \return decrypted data
 *      NOTE: inba don't need to contains wholed data that is
 *      encrypted to operate corectly it can be small chunk of
 *      i.e. whole file
 */

QByteArray MCrypto::decrypt(const QByteArray &inba, const QByteArray &pwd)
{
    QByteArray outbuf;

#ifdef HAS_OPENSSL
    if (initDec(pwd))
    {
        int inlen = 0, outlen = 0;
            inlen = inba.size();

        outbuf = QByteArray(inlen + EVP_MAX_BLOCK_LENGTH, 0);

        if (!EVP_DecryptUpdate(&d_ctx, (unsigned char*)outbuf.data(), &outlen,
                               (const unsigned char*)inba.constData(), inlen)) {
            return QByteArray();
        }

        int tmplen = 0;

        if (!EVP_DecryptFinal_ex(&d_ctx,
                                 ((unsigned char*)outbuf.data()) + outlen, &tmplen)) {
            qDebug() << "--- !EVP_EncryptFinal_ex";
            return QByteArray();
        }

        outlen += tmplen;

        EVP_CIPHER_CTX_cleanup(&d_ctx);
        EVP_cleanup();

        outbuf.resize(outlen);
    }
    else
      qCritical() << "Unable to init decode crypt!";
#else
    QByteArray hashKey = QCryptographicHash::hash(pwd, QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(QByteArray(), QCryptographicHash::Md5);

    // converted to QString because QAesEncryption added null bytes at the end
    return QString(QAESEncryption::Decrypt(encryption, encryptionMode, inba, hashKey, hashIV)).toLocal8Bit();
#endif

    return outbuf;
}
