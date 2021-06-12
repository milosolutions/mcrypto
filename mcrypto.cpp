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

#ifdef USING_OPENSSL
    #include "backend/mcb_openssl.h"
#else
    #include "backend/mcb_qaes.h"
#endif


/*!
 * \brief Encryption wrapper for 3rd party AES implementations
 *
 *  Wrapper provides easy to use interfaces to minimize time spent
 *  on configuring encryption libs.
 *
 *  There are two backends that implement AES standard:
 *
 *  * OpenSSL (recommended)
 *  * QAESEncryption
 *
 *  If OpenSSL development files are not detected QAESEncryption will be used
 *  as fallback backend.
 *
 *  NOTICE: MacOsX uses it's own implementation that differes from OpenSSL one
 *  that's why it will generate deprecated functions warnings.
 *  To bypass this link statically to OpenSSL.
 */
MCrypto::MCrypto(AES_TYPE bits, MODE mode) : backend(bits, mode)
{
#ifdef USING_OPENSSL
    backend = new MCB_OpenSsl(bits, mode);
#else
    backend = new MCB_QAes(bits, mode);
#endif
}

MCrypto::~MCrypto()
{
    delete backend;
}

/*!
 * Convenience method. Creates MCrypto object and run encrypt method on it.
 * \sa MCrypto::MCrypto
 * \sa MCrypto::encrypt
 */
QByteArray MCrypto::encrypt(const MCrypto::AES_TYPE bits, const MCrypto::MODE mode,
                            const QByteArray &input, const QByteArray &pwd,
                            const QByteArray &salt)
{
    return MCrypto(bits, mode).encrypt(input, pwd, salt);
}

/*!
 * Convenience method. Creates MCrypto object and run decrypt method on it.
 * \sa MCrypto::MCrypto
 * \sa MCrypto::decrypt
 */
QByteArray MCrypto::decrypt(const AES_TYPE bits, const MCrypto::MODE mode,
                            const QByteArray &input, const QByteArray &pwd,
                            const QByteArray &salt)
{
    return MCrypto(bits, mode).decrypt(input, pwd, salt);
}

/*!
 * Encrypt \a input using \a pwd and \a salt.
 * \param input bytes to be encoded
 * \param pwd secret passphrase for generating encryption key
 * \param salt additional random sequence of bytes that will be used to generate Initialization Vectors (IV)
 * \return encrypted data
 */
QByteArray MCrypto::encrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    return backend->encrypt(input, pwd, salt);
}

/*!
 * Decrypt \a input using \a pwd and \a salt.
 * \param input encrypted data for decoding
 * \param pwd secret passphrase used for encryption of \a input data
 * \param salt must be the same as used for encryption of that particular data passed as \a input
 * \return decrypted data
 * \sa MCrypto::encrypt
 *
 * NOTE: \a input doesn't need to contain whole data that is
 *      encrypted to operate corectly - it can be small chunk of bigger
 *      data sequence i.e. part of file
 */
QByteArray MCrypto::decrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    return backend->decrypt(input, pwd, salt);
}
