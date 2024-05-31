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
    1.qss \
    app.manifest \
    xxfer.ico

RESOURCES += \
    img_src.qrc

RC_ICONS = logo.ico

# WinSock
LIBS += -lws2_32
LIBS += -liphlpapi

INCLUDEPATH += "D:\Tools\github\personal\Projects\XScanner\qt\WpdPack/Include"
LIBS += "-LD:\Tools\github\personal\Projects\XScanner\qt\WpdPack/Lib/x64" -lwpcap -lPacket

