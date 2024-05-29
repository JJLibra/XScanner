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

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
