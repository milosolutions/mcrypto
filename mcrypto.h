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
    ~MCrypto();

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

    class Backend {
    public:
        virtual ~Backend() = default;
        virtual QByteArray encrypt(const QByteArray &inba, const QByteArray &pwd) = 0;
        virtual QByteArray decrypt(const QByteArray &inba, const QByteArray &pwd) = 0;
    };

 private:
    Backend *backend{nullptr};
};

#endif // ENCRYPTION_H
