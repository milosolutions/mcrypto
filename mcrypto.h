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

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <QObject>
#include <QDebug>

#if !defined (DISABLE_OPENSSL) && defined(OPENSSL_INCLUDED)
    #include "openssl/evp.h"
    #define HAS_OPENSSL
#endif

#include "qaesencryption.h"

class Crypto : public QObject
{
    Q_OBJECT
public:
    typedef enum {
        AES_128,
        AES_192,
        AES_256
    } AES;

    typedef enum {
        ECB,
        CBC,
        CFB
    } MODE;

    explicit Crypto(const Crypto::AES encryption = Crypto::AES_256, const Crypto::MODE mode = Crypto::CBC, QObject *parent = 0);

    static QByteArray encrypt(const Crypto::AES level, const Crypto::MODE mode, QByteArray &rawText, const QString &key, const QByteArray &iv = QByteArray());
    static QByteArray decrypt(const Crypto::AES level, const Crypto::MODE mode, QByteArray &encryptedText, const QString &key, const QByteArray &iv = QByteArray());

    QByteArray encrypt(QByteArray &inba, const QString &pwd);
    QByteArray decrypt(QByteArray &inba, const QString &pwd);

private:
    bool initEnc(const QString &pwd);
    bool initDec(const QString &pwd);

    static QString getAlgorithmName(const Crypto::AES level,const  Crypto::MODE mode);
    static QAESEncryption::AES aesToQAesEnc(const Crypto::AES level);
    static QAESEncryption::MODE modeToQAesMode(const Crypto::MODE level);

#ifdef HAS_OPENSSL
    EVP_CIPHER_CTX e_ctx;
    EVP_CIPHER_CTX d_ctx;
    QByteArray key;
    QByteArray iv;
    QString algorithm;
#endif
    QAESEncryption::AES encryption;
    QAESEncryption::MODE encryptionMode;

    QByteArray salt;
    
signals:
    
public slots:
    
};

#endif // ENCRYPTION_H
