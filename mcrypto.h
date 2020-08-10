/*******************************************************************************
Copyright (C) 2020 Milo Solutions
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

        class MCrypto
{
    Q_GADGET
 public:
    enum AES {
        AES_128,
        AES_192,
        AES_256
    };
    Q_ENUM(AES)

    typedef enum MODE {
        ECB,
        CBC,
        CFB
    } MODE;
    Q_ENUM(MODE)

    explicit MCrypto(const MCrypto::AES encryption = MCrypto::AES_256,
                     const MCrypto::MODE mode = MCrypto::CBC);

    Q_INVOKABLE static QByteArray encrypt(const MCrypto::AES level,
                                          const MCrypto::MODE mode,
                                          const QByteArray &rawText,
                                          const QByteArray &key,
                                          const QByteArray &iv = QByteArray());
    Q_INVOKABLE static QByteArray decrypt(const MCrypto::AES level,
                                          const MCrypto::MODE mode,
                                          const QByteArray &encryptedText,
                                          const QByteArray &key,
                                          const QByteArray &iv = QByteArray());

    Q_INVOKABLE QByteArray encrypt(const QByteArray &inba, const QByteArray &pwd);
    Q_INVOKABLE QByteArray decrypt(const QByteArray &inba, const QByteArray &pwd);

 private:
    bool initEnc(const QByteArray &pwd);
    bool initDec(const QByteArray &pwd);

    static QAESEncryption::AES aesToQAesEnc(const MCrypto::AES level);
    static QAESEncryption::MODE modeToQAesMode(const MCrypto::MODE level);

#ifdef HAS_OPENSSL
    EVP_CIPHER_CTX *e_ctx = nullptr;
    EVP_CIPHER_CTX *d_ctx = nullptr;
    QByteArray m_key;
    QByteArray m_iv;
    QByteArray m_algorithm;
#endif

    QAESEncryption::AES m_encryption;
    QAESEncryption::MODE m_encryptionMode;

    const QByteArray m_salt;

#ifdef HAS_OPENSSL
    /*!
     * Automatically cleans up EVP_CIPHER_CTX when it goes out of scope.
     */
    class ContextLocker {
     public:
        ContextLocker(EVP_CIPHER_CTX *context) : m_context(context) {}
        ~ContextLocker() {
            if (m_cleanup && m_context) {
                EVP_CIPHER_CTX_cleanup(m_context);
                EVP_CIPHER_CTX_free(m_context);
                EVP_cleanup();
                m_context = nullptr;
            }
        }

        void doNotClean() {
            m_cleanup = false;
        }

     private:
        bool m_cleanup = true;
        EVP_CIPHER_CTX *m_context = nullptr;
    };
#endif
};

#endif // ENCRYPTION_H
