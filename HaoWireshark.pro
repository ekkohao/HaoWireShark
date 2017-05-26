#-------------------------------------------------
#
# Project created by QtCreator 2017-05-20T00:28:48
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = HaoWireshark
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

INCLUDEPATH += E:\__Source\WpdPack\Include

LIBS += E:\__Source\WpdPack\Lib\wpcap.lib
LIBS += E:\__Source\WpdPack\Lib\Packet.lib

LIBS += -lws2_32
LIBS += -liphlpapi

SOURCES += main.cpp\
        mainwindow.cpp \
    pcapcommon.cpp \
    tcpipcommon.cpp \
    sharkqthread.cpp \
    netprotocol.cpp \
    aboutbox.cpp

HEADERS  += mainwindow.h \
    pcapcommon.h \
    tcpipcommon.h \
    sharkqthread.h \
    netprotocol.h \
    aboutbox.h

FORMS    += mainwindow.ui \
    aboutbox.ui

RC_FILE = myico.rc

RESOURCES += \
    image.qrc
