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

#include <QtTest>
#include <QCoreApplication>

#include "mcrypto.h"

class TestMCrypto : public QObject
{
   Q_OBJECT
private slots:
    void test_encryption_decryption();
    void test_custom_salt();
};

void TestMCrypto::test_encryption_decryption()
{
    const QByteArray pass(TestMCrypto::metaObject()->className());
    const QByteArray data("The Advanced Encryption Standard (AES).");

    const QByteArray encryptedData = MCrypto::encrypt(MCrypto::AES_256,
                                                      MCrypto::CBC,
                                                      data, pass);
    const QByteArray decryptedData = MCrypto::decrypt(MCrypto::AES_256,
                                                      MCrypto::CBC,
                                                      encryptedData, pass);

    QCOMPARE(data, decryptedData);
}

void TestMCrypto::test_custom_salt()
{
    // Having 2 objects crypt1 and crypt2 simulate
    // passing message between two separate parties
    // encryption algorithm details must be well established
    // pass (user provided) and salt (machine provided) must be shared
    const QByteArray msg("Secret message to be encrypted.");
    const QByteArray pass(TestMCrypto::metaObject()->className());
    const QByteArray salt(TestMCrypto::metaObject()->className());

    // Sender
    MCrypto crypt1(MCrypto::AES_256, MCrypto::CBC);
    const QByteArray encryptedData = crypt1.encrypt(msg, pass, salt);
    // encrypted data will be delivered to receiver

    // Receiver
    MCrypto crypt2(MCrypto::AES_256, MCrypto::CBC);
    const QByteArray decryptedData = crypt2.decrypt(encryptedData, pass, salt);

    QCOMPARE(msg, decryptedData);
}


QTEST_MAIN(TestMCrypto)

#include "tst_mcrypto.moc"
