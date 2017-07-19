isEmpty(OPENSSL_PATH) {
  win32:OPENSSL_PATH=$$PWD/OpenSSL-Win32
  unix:OPENSSL_PATH=/usr/include/openssl
  android:OPENSSL_PATH=$$PWD/OpenSSL-for-Android-Prebuilt
}

isEmpty(OPENSSL_INCLUDE) {
  unix:OPENSSL_INCLUDE=/usr/include/openssl
}

win32 {
    exists($$OPENSSL_PATH/include/*) {
        LIBS += -L$$OPENSSL_PATH/lib -lssleay32 -llibeay32
        INCLUDEPATH += $$OPENSSL_PATH/include
        DEFINES += OPENSSL_INCLUDED
    }
}
unix {
    exists($$OPENSSL_PATH/*) {
        LIBS += -lssl -lcrypto
        INCLUDEPATH += $$OPENSSL_INCLUDE
        DEFINES += OPENSSL_INCLUDED
    }
}
android {
    exists($$OPENSSL_PATH/include/*) {
        INCLUDEPATH += $$OPENSSL_PATH/include
        LIBS += -L$$OPENSSL_PATH/armeabi-v7a/lib -lssl -lcrypto
        DEFINES += OPENSSL_INCLUDED
    }
}

INCLUDEPATH += $$PWD

SOURCES += $$PWD\mcrypto.cpp \
    $$PWD\qaesencryption.cpp

HEADERS += $$PWD\mcrypto.h \
    $$PWD\qaesencryption.h
