MCrypto
===

[Online documentation](https://docs.milosolutions.com/milo-code-db/mcrypto)

[Source code](https://github.com/milosolutions/mcrypto)

\tableofcontents

# Description

Cryptographic API for Qt applications. It allow to encode and decode AES 128, 192, 256 in CBC, ECB or CFB modes. If OpenSSL isn't included, [Qt-AES](https://github.com/bricke/Qt-AES) will be used.

# Building

1. Include mcrypto.pri to your .pro file.
2. If OpenSSL is not included Qt-AES will be used
3. You can use CONFIG += openssl / no-openssl to force either setting.
4. Enjoy.
5. If something does not work, see the mcrypto.pri - perhaps the paths are wrong?

## Including OpenSSL

### Defines

```
OPENSSL_PATH - custom OpenSSL path
OPENSSL_INCLUDE - custom OpenSSL include path
```

### Windows

1. Download version below 1.1.0 [OpenSSL download] (https://slproweb.com/products/Win32OpenSSL.html). 
2. Extract into project directory (with location of mcrypt.pri).
3. After building copy libeay32.dll and ssleay32.dll to .exe location or windows directory.

### Linux

```
sudo apt install libssl-dev
```

Or, use custom build script from mcrypto/scripts/prepare_openssl_linux.sh directory and update paths in mcrypto.pri.

### Android

1. Prepare mcrypto/scripts/setenv-android.sh (copy the example, fill in correct data).
2. Run ```./prepare_openssl_android.sh```
2. Check paths for Android libraries in mcrypto.pri. They should be OK by default.

[Further reading] (http://doc.qt.io/qt-5/opensslsupport.html)

# Examples

For security reasons remember to not save ***password***, ***IV*** or ***salt*** as plain string in source code! Examples show one way to save password without revealing it.

## Encoding

	Crypto crypt(Crypto::AES_256, Crypto::CBC);
	
	QByteArray password(SomeClass::staticMetaObject.className() + QByteArray("12") + SomeOtherClass::metaEnum + QByteArray::number(0x11abc126));
	QByteArray rawData = ...;
	
	QByteArray encryptedData = crypt.encrypt(rawText, password);

## Decoding

	Crypto crypt(Crypto::AES_256, Crypto::CBC);
	
	QByteArray password(SomeClass::staticMetaObject.className() + QByteArray("12") + SomeOtherClass::metaEnum + QByteArray::number(0x11abc126));
	QByteArray encryptedData = ...;
	
	QByteArray rawData = crypt.decrypt(encryptedData, password);

## Static calls

    QByteArray password(SomeClass::staticMetaObject.className() + QByteArray("12") + SomeOtherClass::metaEnum + QByteArray::number(0x11abc126));
    QByteArray rawData("The Advanced Encryption Standard (AES)");
    QByteArray iv("");

	Crypto::encrypt(Crypto::AES_256, Crypto::CBC, rawData, password, iv);
  
# Dependencies

* OpenSSL (below verison 1.1)
* Qt-AES  (Reference link: https://github.com/bricke/Qt-AES)
	
# License

This project is licensed under the MIT License - see the LICENSE-MiloCodeDB.txt file for details
