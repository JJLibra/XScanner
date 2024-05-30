QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

SOURCES += \
    hostscannerwindow.cpp \
    main.cpp \
    mainwindow.cpp \
    portscannerwindow.cpp

HEADERS += \
    hostscannerwindow.h \
    mainwindow.h \
    portscannerwindow.h

FORMS += \
    hostscannerwindow.ui \
    mainwindow.ui \
    portscannerwindow.ui

qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    xxfer.ico

RESOURCES += \
    img_src.qrc

RC_ICONS = xxfer.ico

win32:LIBS += -lws2_32 -liphlpapi
