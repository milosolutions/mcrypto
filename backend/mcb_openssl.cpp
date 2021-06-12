#include "mcrypto.h"
#include <QDebug>
#include <QMetaEnum>
#include <openssl/evp.h>

// Automatically cleans up EVP_CIPHER_CTX when it goes out of scope.
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
    bool m_cleanup{true};
    EVP_CIPHER_CTX *m_context{nullptr};
};

struct MCrypto::InternalData
{
    bool initEnc(const QByteArray &pwd, const QByteArray &customSalt);
    bool initDec(const QByteArray &pwd, const QByteArray &customSalt);
    EVP_CIPHER_CTX *e_ctx = nullptr;
    EVP_CIPHER_CTX *d_ctx = nullptr;
    QByteArray key;
    QByteArray iv;
    QByteArray algorithm;
    const QByteArray salt{MCrypto::staticMetaObject.className()
                + QByteArray("12")
                + QByteArray::number(0x11abc126)};
};

bool MCrypto::InternalData::initEnc(const QByteArray &pwd, const QByteArray &customSalt)
{
    key = QByteArray(EVP_MAX_KEY_LENGTH, 0);
    iv = QByteArray(EVP_MAX_IV_LENGTH, 0);
    auto salt = reinterpret_cast<const unsigned char *>(
                customSalt.isNull()? this->salt.constData() : customSalt.constData());

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    if (e_ctx) { // Clean up old CTX if present
        ContextLocker locker(e_ctx);
    }
    e_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(e_ctx);
    ContextLocker locker(e_ctx);

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(qPrintable(algorithm));
    if (!cipher) {
        return false;
    }

    const EVP_MD *dgst = EVP_get_digestbyname(qPrintable("md5"));

    if (!dgst) {
        return false;
    }

    if(!EVP_BytesToKey(cipher, dgst, salt,
                        (const unsigned char *) pwd.constData(), pwd.size(),
                        1, (unsigned char *)key.data(), (unsigned char *)iv.data()))
    {
        return false;
    }

    if (key.isEmpty() || iv.isEmpty()) {
        return false;
    }

    if (!EVP_EncryptInit_ex(e_ctx, cipher, nullptr,
                            (const unsigned char*)key.constData(),
                            (const unsigned char*)iv.constData())) {
        return false;
    }

    locker.doNotClean();
    return true;
}

bool MCrypto::InternalData::initDec(const QByteArray &pwd, const QByteArray &customSalt)
{
    key = QByteArray(EVP_MAX_KEY_LENGTH, 0);
    iv = QByteArray(EVP_MAX_IV_LENGTH, 0);
    auto salt = reinterpret_cast<const unsigned char *>(
                customSalt.isNull()? this->salt.constData() : customSalt.constData());

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    if (d_ctx) { // Clean up old CTX if present
        ContextLocker locker(d_ctx);
    }
    d_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(d_ctx);

    ContextLocker locker(d_ctx);

    const EVP_CIPHER *decipher = EVP_get_cipherbyname(qPrintable(algorithm));
    if (!decipher) {
        return false;
    }

    const EVP_MD *dgst = EVP_get_digestbyname(qPrintable("md5"));

    if (!dgst) {
        return false;
    }

    if(!EVP_BytesToKey(decipher, dgst, salt,
                        (const unsigned char *) pwd.constData(), pwd.size(),
                        1, (unsigned char *)key.data(), (unsigned char *)iv.data()))
    {
        return false;
    }

    if (key.isEmpty() || iv.isEmpty()) {
        return false;
    }

    if (!EVP_DecryptInit_ex(d_ctx, decipher, nullptr,
                            (const unsigned char*)key.constData(),
                            (const unsigned char*)iv.constData())) {
        return false;
    }

    locker.doNotClean();
    return true;
}

MCrypto::Backend::Backend(MCrypto::KEY_SIZE bits, MCrypto::MODE mode)
{
    m = new InternalData;
    m->algorithm = QByteArray(QMetaEnum::fromType<MCrypto::KEY_SIZE>()
                                 .valueToKey(int(bits))).replace('_', '-')
                  + QByteArray("-")
                  + QByteArray(QMetaEnum::fromType<MCrypto::MODE>().valueToKey(int(mode)));
}

MCrypto::Backend::~Backend()
{
    delete m;
}

QByteArray MCrypto::Backend::encrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    QByteArray outbuf;

    if (m->initEnc(pwd, salt))
    {
        ContextLocker locker(m->e_ctx);
        int inlen = 0, outlen = 0, len = 0;
        inlen = input.size();

        outbuf = QByteArray(inlen + EVP_MAX_BLOCK_LENGTH, 0);

        if (!EVP_EncryptUpdate(m->e_ctx, (unsigned char*)outbuf.data(), &len,
                               (const unsigned char*)input.constData(), inlen)) {
            return QByteArray();
        }

        outlen = len;

        if (!EVP_EncryptFinal_ex(
                m->e_ctx, ((unsigned char*)outbuf.data()) + len, &len)) {
            return QByteArray();
        }

        outlen += len;

        outbuf.resize(outlen);
    } else {
        qCritical() << "Unable to init encode crypt!";
    }

    return outbuf;
}

QByteArray MCrypto::Backend::decrypt(const QByteArray &input, const QByteArray &pwd, const QByteArray &salt)
{
    QByteArray outbuf;

    if (m->initDec(pwd, salt)) {
        ContextLocker locker(m->d_ctx);
        int inlen = 0, outlen = 0;
        inlen = input.size();

        outbuf = QByteArray(inlen + EVP_MAX_BLOCK_LENGTH, 0);

        if (!EVP_DecryptUpdate(m->d_ctx, (unsigned char*)outbuf.data(), &outlen,
                               (const unsigned char*)input.constData(), inlen)) {
            return QByteArray();
        }

        int tmplen = 0;

        if (!EVP_DecryptFinal_ex(m->d_ctx,
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
