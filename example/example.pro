QT += core
QT -= gui

CONFIG += c++11
CONFIG -= app_bundle
TARGET = example-AES
TEMPLATE = app

SOURCES += main.cpp

include(../mcrypto.pri)
