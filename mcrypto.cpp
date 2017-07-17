/*******************************************************************************
Copyright (C) 2016 Milo Solutions
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


/*!
 * \brief crypto functionality base on OpenSSL
 *  NOTICE: MacOsX uses it's own implementation that differes from OpenSSL one
 *        that's why it will generate deprecated functions warnings.
 *        To bypass this link statically OpenSSL.
 */

Crypto::Crypto(const Crypto::AES encryption, const Crypto::MODE mode, QObject *parent)
  : QObject(parent)
  , encryption(aesToQAesEnc(encryption))
  , encryptionMode(modeToQAesMode(mode))
{
    salt = QString("d3aaa3a6b83786a20fcb6feda5b7c613b6421bb1b731a318903b95e18d6e6ecf").toLatin1();

#ifdef HAS_OPENSSL
    algorithm = Crypto::getAlgorithmName(encryption, mode);
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

QByteArray Crypto::encrypt(const Crypto::AES level, const Crypto::MODE mode, QByteArray &rawText, const QString &key, const QByteArray &iv)
{
#ifdef HAS_OPENSSL
    qDebug() << Q_FUNC_INFO << "OpenSSL";
    Q_UNUSED(iv);
    return Crypto(level, mode).encrypt(rawText, key);

#else

    qDebug() << Q_FUNC_INFO << "Qt-AES";
    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(iv, QCryptographicHash::Md5);

    return QAESEncryption::Crypt(Crypto::aesToQAesEnc(level), modeToQAesMode(mode), rawText, hashKey, hashIV);

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
QByteArray Crypto::decrypt(const Crypto::AES level, const Crypto::MODE mode, QByteArray &encryptedText, const QString &key, const QByteArray &iv)
{
#ifdef HAS_OPENSSL
    qDebug() << Q_FUNC_INFO << "OpenSSL";
    Q_UNUSED(iv);
    return Crypto(level, mode).decrypt(encryptedText, key);
#else
    qDebug() << Q_FUNC_INFO << "Qt-AES";
    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(iv, QCryptographicHash::Md5);

    // converted to QString because QAesEncryption added null bytes at the end
    return QString(QAESEncryption::Decrypt(Crypto::aesToQAesEnc(level), modeToQAesMode(mode), encryptedText, hashKey, hashIV)).toLocal8Bit();

#endif
}

/*!
 * \brief Convert Crypto::AES to QAESEncryption::AES
 * \param level
 * \return Converted aes enum
 */
QAESEncryption::AES Crypto::aesToQAesEnc(const Crypto::AES level)
{
  switch(level)
  {
    case Crypto::AES_128:
      return QAESEncryption::AES_128;
    case Crypto::AES_192:
      return QAESEncryption::AES_192;
    default:
    case Crypto::AES_256:
      return QAESEncryption::AES_256;
  }
}

/*!
 * \brief Convert Crypto::MODE to QAESEncryption::MODE
 * \param mode
 * \return Converted mode enum
 */

QAESEncryption::MODE Crypto::modeToQAesMode(const Crypto::MODE mode)
{
  switch(mode)
  {
    default:
    case Crypto::CBC:
      return QAESEncryption::CBC;
    case Crypto::CFB:
      return QAESEncryption::CFB;
    case Crypto::ECB:
      return QAESEncryption::ECB;
  }
}

/*!
 * \brief Convert encryption level and mode enums to string
 * \param level
 * \param mode
 * \return Algorithm name string
 */

QString Crypto::getAlgorithmName(const Crypto::AES level, const Crypto::MODE mode)
{
  QString name = QString();

  switch(level)
  {
    case Crypto::AES_128:
      name = "aes-128";
      break;
    case Crypto::AES_192:
      name = "aes-192";
      break;
    case Crypto::AES_256:
      name = "aes-256";
      break;
  }

  switch(mode)
  {
    case Crypto::CBC:
      name += "-cbc";
      break;
    case Crypto::CFB:
      name += "-cfb";
      break;
    case Crypto::ECB:
      name += "-ecb";
      break;
    default:
      break;
  }

  return name;
}

/*!
 * \brief init encryption algorithm
 * \param pwd if empty content is NOT encrypted
 * \return true on success
 */

bool Crypto::initEnc(const QString &pwd)
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

QByteArray Crypto::encrypt(QByteArray &inba, const QString &pwd)
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
    QByteArray hashKey = QCryptographicHash::hash(pwd.toLocal8Bit(), QCryptographicHash::Sha256);
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

bool Crypto::initDec(const QString &pwd)
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

QByteArray Crypto::decrypt(QByteArray &inba, const QString &pwd)
{
//    qDebug() << Q_FUNC_INFO << inba.size() << isEnd;

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
    QByteArray hashKey = QCryptographicHash::hash(pwd.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(QByteArray(), QCryptographicHash::Md5);

    // converted to QString because QAesEncryption added null bytes at the end
    return QString(QAESEncryption::Decrypt(encryption, encryptionMode, inba, hashKey, hashIV)).toLocal8Bit();
#endif

    return outbuf;
}
