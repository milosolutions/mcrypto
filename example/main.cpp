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

#include <QDebug>

#include "mcrypto.h"

void test(QByteArray &rawData, const QString &pass)
{
  qDebug().nospace() << "\n" << Q_FUNC_INFO;
  Crypto crypt(Crypto::AES_256, Crypto::CBC);
  QByteArray encryptedData = crypt.encrypt(rawData, pass);
  qDebug() << "Encryption result:" << encryptedData;

  Crypto crypt2(Crypto::AES_256, Crypto::CBC);
  QByteArray decryptedData = crypt2.decrypt(encryptedData, pass);
  qDebug() << "Decryption result:" << decryptedData;
}

void testStatic(QByteArray &rawData, const QString &pass)
{
  qDebug().nospace() << "\n" << Q_FUNC_INFO;
  QByteArray encryptedData = Crypto::encrypt(Crypto::AES_256, Crypto::CBC, rawData, pass);
  qDebug() << "Encryption result:" << encryptedData;

  QByteArray decryptedData = Crypto::decrypt(Crypto::AES_256, Crypto::CBC, encryptedData, pass);
  qDebug() << "Decryption result:" << decryptedData;
}


int main(int argc, char *argv[])
{
  Q_UNUSED(argc);
  Q_UNUSED(argv);

  QString pass = "password";
  QByteArray rawData = "The Advanced Encryption Standard (AES)";

  test(rawData, pass);
  testStatic(rawData, pass);

  return 1;
}

