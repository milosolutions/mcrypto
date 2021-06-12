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
    enum KEY_SIZE {
        KEY_128,
        KEY_192,
        KEY_256
    };
    Q_ENUM(KEY_SIZE)

    typedef enum MODE {
        ECB,
        CBC,
        CFB
    } MODE;
    Q_ENUM(MODE)

    explicit MCrypto(KEY_SIZE encryption = KEY_256, MODE mode = CBC);
    ~MCrypto();

    Q_INVOKABLE static QByteArray encrypt(KEY_SIZE bits,
                                          MODE mode,
                                          const QByteArray &input,
                                          const QByteArray &pwd,
                                          const QByteArray &salt = {});
    Q_INVOKABLE static QByteArray decrypt(KEY_SIZE bits,
                                          MODE mode,
                                          const QByteArray &input,
                                          const QByteArray &pwd,
                                          const QByteArray &salt = {});

    Q_INVOKABLE QByteArray encrypt(const QByteArray &input,
                                   const QByteArray &pwd,
                                   const QByteArray &salt = {});
    Q_INVOKABLE QByteArray decrypt(const QByteArray &input,
                                   const QByteArray &pwd,
                                   const QByteArray &salt = {});

    class Backend {
    public:
        virtual ~Backend() = default;
        virtual QByteArray encrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt) = 0;
        virtual QByteArray decrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt) = 0;
    };

 private:
    Backend *backend{nullptr};
};

#endif // ENCRYPTION_H
