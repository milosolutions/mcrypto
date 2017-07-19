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
#include <QLoggingCategory>

#include "mcrypto.h"

Q_LOGGING_CATEGORY(coreMain, "core.main")

void test(QByteArray &rawData, const QByteArray &pass)
{
  qCDebug(coreMain) << Q_FUNC_INFO;
  MCrypto crypt(MCrypto::AES_256, MCrypto::CBC);
  QByteArray encryptedData = crypt.encrypt(rawData, pass);
  qCDebug(coreMain) << "Encryption result:" << encryptedData;

  MCrypto crypt2(MCrypto::AES_256, MCrypto::CBC);
  QByteArray decryptedData = crypt2.decrypt(encryptedData, pass);
  qCDebug(coreMain) << "Decryption result:" << decryptedData;
}

void testStatic(QByteArray &rawData, const QByteArray &pass)
{
  qCDebug(coreMain) << Q_FUNC_INFO;
  QByteArray encryptedData = MCrypto::encrypt(MCrypto::AES_256, MCrypto::CBC, rawData, pass);
  qCDebug(coreMain) << "Encryption result:" << encryptedData;

  QByteArray decryptedData = MCrypto::decrypt(MCrypto::AES_256, MCrypto::CBC, encryptedData, pass);
  qCDebug(coreMain) << "Decryption result:" << decryptedData;
}


int main(int argc, char *argv[])
{
  Q_UNUSED(argc);
  Q_UNUSED(argv);

  QByteArray pass = "Don't store password as plain string!";
  QByteArray rawData = "The Advanced Encryption Standard (AES)";

  test(rawData, pass);
  testStatic(rawData, pass);

  return 1;
}

