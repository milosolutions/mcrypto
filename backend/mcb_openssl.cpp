#include "mcb_openssl.h"
#include <QDebug>
#include <QMetaEnum>
#include <openssl/evp.h>

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

MCB_OpenSsl::MCB_OpenSsl(MCrypto::KEY_SIZE bits, MCrypto::MODE mode)
    : // Salt mustn't be saved as plain string!
      m_salt(QByteArray(MCrypto::staticMetaObject.className()
                        + QByteArray("12")
                        + QByteArray::number(0x11abc126)))
{
    m_algorithm = QByteArray(QMetaEnum::fromType<MCrypto::KEY_SIZE>()
                                 .valueToKey(int(bits))).replace('_', '-')
                  + QByteArray("-")
                  + QByteArray(QMetaEnum::fromType<MCrypto::MODE>().valueToKey(int(mode)));
}

QByteArray MCB_OpenSsl::encrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    QByteArray outbuf;

    if (initEnc(pwd))
    {
        ContextLocker locker(e_ctx);
        int inlen = 0, outlen = 0, len = 0;
        inlen = input.size();

        outbuf = QByteArray(inlen + EVP_MAX_BLOCK_LENGTH, 0);

        if (!EVP_EncryptUpdate(e_ctx, (unsigned char*)outbuf.data(), &len,
                               (const unsigned char*)input.constData(), inlen)) {
            return QByteArray();
        }

        outlen = len;

        if (!EVP_EncryptFinal_ex(
                e_ctx, ((unsigned char*)outbuf.data()) + len, &len)) {
            return QByteArray();
        }

        outlen += len;

        outbuf.resize(outlen);
    } else {
        qCritical() << "Unable to init encode crypt!";
    }

    return outbuf;
}

QByteArray MCB_OpenSsl::decrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    QByteArray outbuf;

    if (initDec(pwd)) {
        ContextLocker locker(d_ctx);
        int inlen = 0, outlen = 0;
        inlen = input.size();

        outbuf = QByteArray(inlen + EVP_MAX_BLOCK_LENGTH, 0);

        if (!EVP_DecryptUpdate(d_ctx, (unsigned char*)outbuf.data(), &outlen,
                               (const unsigned char*)input.constData(), inlen)) {
            return QByteArray();
        }

        int tmplen = 0;

        if (!EVP_DecryptFinal_ex(d_ctx,
                                 ((unsigned char*)outbuf.data()) + outlen, &tmplen)) {
            qDebug() << "--- !EVP_EncryptFinal_ex";
            return QByteArray();
        }

        outlen += tmplen;

        outbuf.resize(outlen);
    } else {
        qCritical() << "Unable to init decode crypt!";
    }

    return outbuf;
}

/*!
 * \brief init encryption algorithm
 * \param pwd if empty content is NOT encrypted
 * \return true on success
 */
bool MCB_OpenSsl::initEnc(const QByteArray &pwd)
{
    m_key.clear();
    m_iv.clear();

    m_key = QByteArray(EVP_MAX_KEY_LENGTH, 0);
    m_iv = QByteArray(EVP_MAX_IV_LENGTH, 0);

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    if (e_ctx) { // Clean up old CTX if present
        ContextLocker locker(e_ctx);
    }
    e_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(e_ctx);
    ContextLocker locker(e_ctx);

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(qPrintable(m_algorithm));
    if (!cipher) {
        return false;
    }

    const EVP_MD *dgst = EVP_get_digestbyname(qPrintable("md5"));

    if (!dgst) {
        return false;
    }

    if(!EVP_BytesToKey(cipher, dgst, (const unsigned char *) m_salt.constData(),
                        (const unsigned char *) pwd.constData(), pwd.size(),
                        1, (unsigned char *)m_key.data(), (unsigned char *)m_iv.data()))
    {
        return false;
    }

    if (m_key.isEmpty() || m_iv.isEmpty()) {
        return false;
    }

    if (!EVP_EncryptInit_ex(e_ctx, cipher, nullptr,
                            (const unsigned char*)m_key.constData(),
                            (const unsigned char*)m_iv.constData())) {
        return false;
    }

    locker.doNotClean();
    return true;
}

/*!
 * \brief initialise decoder to use
 * \param pwd
 * \return initialization status
 */
bool MCB_OpenSsl::initDec(const QByteArray &pwd)
{
    m_key.clear();
    m_iv.clear();

    m_key = QByteArray(EVP_MAX_KEY_LENGTH, 0);
    m_iv = QByteArray(EVP_MAX_IV_LENGTH, 0);

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    if (d_ctx) { // Clean up old CTX if present
        ContextLocker locker(d_ctx);
    }
    d_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(d_ctx);

    ContextLocker locker(d_ctx);

    const EVP_CIPHER *decipher = EVP_get_cipherbyname(qPrintable(m_algorithm));
    if (!decipher) {
        return false;
    }

    const EVP_MD *dgst = EVP_get_digestbyname(qPrintable("md5"));

    if (!dgst) {
        return false;
    }

    if(!EVP_BytesToKey(decipher, dgst, (const unsigned char *) m_salt.constData(),
                        (const unsigned char *) pwd.constData(), pwd.size(),
                        1, (unsigned char *)m_key.data(), (unsigned char *)m_iv.data()))
    {
        return false;
    }

    if (m_key.isEmpty() || m_iv.isEmpty()) {
        return false;
    }

    if (!EVP_DecryptInit_ex(d_ctx, decipher, nullptr,
                            (const unsigned char*)m_key.constData(),
                            (const unsigned char*)m_iv.constData())) {
        return false;
    }

    locker.doNotClean();
    return true;
}
