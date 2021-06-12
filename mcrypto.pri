isEmpty(OPENSSL_PATH) {
  win32:OPENSSL_PATH=$$PWD/OpenSSL-Win32
  unix:OPENSSL_PATH=/usr/include/openssl
  android:OPENSSL_PATH=$$PWD/scripts/OpenSSL/android/armeabi-v7a
}

isEmpty(OPENSSL_INCLUDE) {
  unix:OPENSSL_INCLUDE=/usr/include/openssl
}

win32 {
    exists($$OPENSSL_PATH/include/*) {
        LIBS += -L$$OPENSSL_PATH/lib -lssleay32 -llibeay32
        INCLUDEPATH += $$OPENSSL_PATH/include
        CONFIG += openssl
    }
}
unix {
    exists($$OPENSSL_PATH/*) {
        LIBS += -lssl -lcrypto
        INCLUDEPATH += $$OPENSSL_INCLUDE
        CONFIG += openssl
    }
}
android {
    exists($$OPENSSL_PATH/include/*) {
        INCLUDEPATH += $$OPENSSL_PATH/include
        LIBS += -L$$OPENSSL_PATH/lib -lssl -lcrypto
        CONFIG += openssl
    }
}

INCLUDEPATH += $$PWD
SOURCES += $$PWD/mcrypto.cpp
HEADERS += $$PWD/mcrypto.h
DEFINES += MCRYPTO_LIB

no-openssl {
    CONFIG -= openssl
}

openssl {
    message("MCrypto: using OpenSSL")
    SOURCES += $$PWD/backend/mcb_openssl.cpp
} else {
    message("MCrypto: using default backend (not OpenSSL). Warning: it has not undergone security audit!")
    SOURCES += $$PWD/backend/mcb_qaes.cpp $$PWD/backend/qaesencryption.cpp
}
