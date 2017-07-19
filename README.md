\anchor MCrypto
[TOC]

Milo Code DB main ([online](https://qtdocs.milosolutions.com/milo-code-db/main/) | [offline](\ref milodatabasemain))

# Description

Cryptographic API for Qt applications. It allow to encode and decode AES 128, 192, 256 in CBC, ECB or CFB modes. It is using OpenSSL libraries or included Qt-AES.

# Building

1. Include crypto.pri to your .pro file.
2. If OpenSSL not included included Qt-AES will be used
3. Enjoy.

## Including OpenSSL

### Defines

* OPENSSL_PATH - custom OpenSSL path
* OPENSSL_INCLUDE - custom OpenSSL include path

### Windows

1. Download version below 1.1.0 [OpenSSL download] (https://slproweb.com/products/Win32OpenSSL.html). 
2. Extract into project directory (with location of mcrypt.pri).
3. After building copy libeay32.dll and ssleay32.dll to .exe location or windows directory.

### Linux

1. sudo apt-get install libssl-dev

### Android

1. Prepare OpenSSL for Android: [Qt OpenSSL support] (http://doc.qt.io/qt-5/opensslsupport.html)
2. Update path for android libraries in mcrypto.pri

# Examples

For security reasons remember to not save ***password***, ***IV*** or ***salt*** as plain string in source code! Examples show one way to save password without revealing it.

### Encoding

	Crypto crypt(Crypto::AES_256, Crypto::CBC);
	
	QByteArray password(SomeClass::staticMetaObject.className() + QByteArray("12") + SomeOtherClass::metaEnum + QByteArray::number(0x11abc126));
	QByteArray rawData = ...;
	
	QByteArray encryptedData = crypt.encrypt(rawText, password);

### Decoding

	Crypto crypt(Crypto::AES_256, Crypto::CBC);
	
	QByteArray password(SomeClass::staticMetaObject.className() + QByteArray("12") + SomeOtherClass::metaEnum + QByteArray::number(0x11abc126));
	QByteArray encryptedData = ...;
	
	QByteArray rawData = crypt.decrypt(encryptedData, password);

### Static calls

    QByteArray password(SomeClass::staticMetaObject.className() + QByteArray("12") + SomeOtherClass::metaEnum + QByteArray::number(0x11abc126));
    QByteArray rawData("The Advanced Encryption Standard (AES)");
    QByteArray iv("");

  Crypto::encrypt(Crypto::AES_256, Crypto::CBC, rawData, password, iv);
  
# Dependencies

* OpenSSL (below verison 1.1)
* Qt-AES  (Reference link: https://github.com/bricke/Qt-AES)
	
# License

This project is licensed under the MIT License - see the LICENSE-MiloCodeDB.txt file for details