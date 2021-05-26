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

#include "mcrypto.h"

#if !defined (DISABLE_OPENSSL) && defined(OPENSSL_INCLUDED)
    #define HAS_OPENSSL
    #include "backend/mcb_openssl.h"
#else
    #include "backend/mcb_qaes.h"
#endif


/*!
 * \brief crypto functionality based on OpenSSL
 *  NOTICE: MacOsX uses it's own implementation that differes from OpenSSL one
 *        that's why it will generate deprecated functions warnings.
 *        To bypass this link statically to OpenSSL.
 */
MCrypto::MCrypto(const MCrypto::AES encryption, const MCrypto::MODE mode)
{
#ifdef HAS_OPENSSL
    backend = new MCB_OpenSsl(encryption, mode);
#else
    backend = new MCB_QAes(encryption, mode);
#endif
}

MCrypto::~MCrypto()
{
    delete backend;
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
QByteArray MCrypto::encrypt(const MCrypto::AES level, const MCrypto::MODE mode,
                            const QByteArray &rawText, const QByteArray &key,
                            const QByteArray &iv)
{
    // TODO iv vector should be accessible via interface
    Q_UNUSED(iv);
    return MCrypto(level, mode).encrypt(rawText, key);
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
QByteArray MCrypto::decrypt(const MCrypto::AES level, const MCrypto::MODE mode,
                            const QByteArray &encryptedText, const QByteArray &key,
                            const QByteArray &iv)
{
    // TODO iv vector should be accessible via interface
    Q_UNUSED(iv)
    return MCrypto(level, mode).decrypt(encryptedText, key);
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
    return backend->encrypt(inba, pwd);
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
    return backend->decrypt(inba, pwd);
}
