#!/usr/bin/env python3

"""
Copyright (C) 2020, Alexandre Gazet.

This file is part of ret-sync plugin for Binary Ninja.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os

# fmt: off
import binaryninjaui
if 'qt_major_version' in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout, QLabel
    from PySide6.QtGui import QImage
else:
    from PySide2.QtCore import Qt
    from PySide2.QtWidgets import QHBoxLayout, QVBoxLayout, QLabel
    from PySide2.QtGui import QImage

from binaryninjaui import (SidebarWidget, SidebarWidgetType, UIActionHandler,
                           SidebarWidgetLocation, SidebarContextSensitivity)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..sync import SyncPlugin
# fmt: on


class SyncStatus(object):
    IDLE = "idle"
    ENABLED = "listening"
    RUNNING = "connected"


class SyncWidget(SidebarWidget):
    # based on hellosidebar.py
    # from https://github.com/Vector35/binaryninja-api/
    def __init__(self, name, frame, data):
        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel('Status: '))
        self.status = QLabel('idle')
        status_layout.addWidget(self.status)
        status_layout.setAlignment(Qt.AlignCenter)

        client_dbg_layout = QHBoxLayout()
        client_dbg_layout.addWidget(QLabel('Client debugger: '))
        self.client_dbg = QLabel('n/a')
        client_dbg_layout.addWidget(self.client_dbg)
        client_dbg_layout.setAlignment(Qt.AlignCenter)

        client_pgm_layout = QHBoxLayout()
        client_pgm_layout.addWidget(QLabel('Client program: '))
        self.client_pgm = QLabel('n/a')
        client_pgm_layout.addWidget(self.client_pgm)
        client_pgm_layout.setAlignment(Qt.AlignCenter)

        layout = QVBoxLayout()
        layout.addStretch()
        layout.addLayout(status_layout)
        layout.addLayout(client_dbg_layout)
        layout.addLayout(client_pgm_layout)
        layout.addStretch()
        self.setLayout(layout)

    def notifyViewChanged(self, view_frame):
        pass

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    def set_status(self, status):
        if status == SyncStatus.RUNNING:
            self.status.setStyleSheet('color: green')
        elif status == SyncStatus.ENABLED:
            self.status.setStyleSheet('color: blue')
        else:
            self.status.setStyleSheet('')

        self.status.setText(status)

    def set_connected(self, dialect):
        self.set_status(SyncStatus.RUNNING)
        self.client_dbg.setText(dialect)

    def set_program(self, pgm):
        self.client_pgm.setText(pgm)

    def reset_client(self):
        self.set_status(SyncStatus.ENABLED)
        self.client_pgm.setText('n/a')
        self.client_dbg.setText('n/a')

    def reset_status(self):
        self.set_status(SyncStatus.IDLE)
        self.client_pgm.setText('n/a')
        self.client_dbg.setText('n/a')


class SyncWidgetType(SidebarWidgetType):
    def __init__(self, sync_plugin: "SyncPlugin"):
        self.sync_plugin = sync_plugin
        base_dir = os.path.dirname(os.path.abspath(__file__))
        png_path = os.path.join(base_dir, "retsync.png")

        icon = QImage(png_path)
        super().__init__(icon, "ret-sync")

    def createWidget(self, frame, data):
        # This callback is called when a widget needs to be created for a given context. Different
        # widgets are created for each unique BinaryView. They are created on demand when the sidebar
        # widget is visible and the BinaryView becomes active.
        sync_widget = SyncWidget("ret-sync", frame, data)
        self.sync_plugin.widget = sync_widget
        return sync_widget

    def defaultLocation(self):
        # Default location in the sidebar where this widget will appear
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        # Context sensitivity controls which contexts have separate instances of the sidebar widget.
        # Using `contextSensitivity` instead of the deprecated `viewSensitive` callback allows sidebar
        # widget implementations to reduce resource usage.

        # This example widget uses a single instance and detects view changes.
        return SidebarContextSensitivity.SelfManagedSidebarContext
