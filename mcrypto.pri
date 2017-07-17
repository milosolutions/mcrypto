win32 {
    exists($$PWD/OpenSSL-Win32/include/*) {
        LIBS += -L$$PWD/OpenSSL-Win32/lib -lssleay32 -llibeay32
        INCLUDEPATH += $$PWD/OpenSSL-Win32/include
        DEFINES += OPENSSL_INCLUDED
    }
}
unix {
    exists(/usr/include/openssl/*) {
        LIBS += -lssl -lcrypto
        INCLUDEPATH += /usr/include/openssl
        DEFINES += OPENSSL_INCLUDED
    }
}
android {
  exists($$PWD/OpenSSL-for-Android-Prebuilt/include/*) {
    INCLUDEPATH += $$PWD/OpenSSL-for-Android-Prebuilt/include
    LIBS += -L$$PWD/OpenSSL-for-Android-Prebuilt/armeabi-v7a/lib -lssl -lcrypto
    DEFINES += OPENSSL_INCLUDED
  }
}

INCLUDEPATH += $$PWD

SOURCES += $$PWD\mcrypto.cpp \
    $$PWD\qaesencryption.cpp

HEADERS += $$PWD\mcrypto.h \
    $$PWD\qaesencryption.h
