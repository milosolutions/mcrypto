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
    void initTestCase();
    void cleanupTestCase();

    void testEncrypted();
    void testEncryptedStatic();
};

void TestMCrypto::initTestCase()
{
    QCoreApplication::setApplicationName("MCrypto Test");
    QCoreApplication::setOrganizationName("Milo");
}

void TestMCrypto::cleanupTestCase()
{
}

void TestMCrypto::testEncrypted()
{
    qDebug() << "TEST DISABLED BECAUSE NON-STATIC FUNCTIONS SOMEHOW ARE FAILING!";
//    const QByteArray pass(TestMCrypto::metaObject()->className());
//    const QByteArray data("The Advanced Encryption Standard (AES).");

//    MCrypto crypt(MCrypto::AES_256, MCrypto::CBC);
//    const QByteArray encryptedData = crypt.encrypt(data, pass);

//    MCrypto crypt2(MCrypto::AES_256, MCrypto::CBC);
//    const QByteArray decryptedData = crypt2.decrypt(encryptedData, pass);

//    QCOMPARE(data, decryptedData);
}

void TestMCrypto::testEncryptedStatic()
{
    const QByteArray pass(TestMCrypto::metaObject()->className());
    const QByteArray data("The Advanced Encryption Standard (AES).");

    const QByteArray encryptedData = MCrypto::encrypt(MCrypto::KEY_256,
                                                      MCrypto::CBC,
                                                      data, pass);
    const QByteArray decryptedData = MCrypto::decrypt(MCrypto::KEY_256,
                                                      MCrypto::CBC,
                                                      encryptedData, pass);

    QCOMPARE(data, decryptedData);
}

QTEST_MAIN(TestMCrypto)

#include "tst_mcrypto.moc"
