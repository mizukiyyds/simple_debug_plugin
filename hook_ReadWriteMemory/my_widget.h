#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_my_widget.h"
#include <windows.h>
class my_widget : public QMainWindow
{
    Q_OBJECT

public:
    my_widget(QWidget *parent = nullptr);
    ~my_widget();
    void timerEvent(QTimerEvent* event);
    int timer_id=0;
    HANDLE m_hDbgProcess=0;
    DWORD m_pid=0;
private:
    Ui::QtWidgetsApplication1Class ui;
};
