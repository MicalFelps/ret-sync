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

import binaryninjaui
if 'qt_major_version' in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
    from PySide6 import QtCore
    from PySide6.QtCore import Qt
else:
    from PySide2 import QtCore
    from PySide2.QtCore import Qt

from binaryninjaui import UIAction, UIActionHandler, UIContext, UIContextNotification, Sidebar
from binaryninjaui import ViewFrame

from binaryninja.plugin import BackgroundTaskThread, PluginCommand


from collections import OrderedDict
import socket
import io
import sys
import asyncio
import threading
import json
import base64
from pathlib import Path
from pathlib import Path as RemotePath
from dataclasses import dataclass

from .retsync import rsconfig as rsconfig
from .retsync.rsconfig import rs_encode, rs_decode, rs_log, rs_debug, load_configuration
from .retsync.rswidget import SyncWidgetType


# Handlers for [sync] and [notice] messages


class SyncHandler(object):
    """Handles [sync] messages: navigation, comments, cursor queries."""

    def __init__(self, plugin):
        self.plugin = plugin
        self.client = None
        self.req_handlers = {
            'loc':      self.req_loc,
            'rbase':    self.req_rbase,
            'cmd':      self.req_cmd,
            'cmt':      self.req_cmt,
            'rcmt':     self.req_rcmt,
            'fcmt':     self.req_fcmt,
            'cursor':   self.req_cursor,
            'raddr':    self.req_not_implemented,
            'patch':    self.req_not_implemented,
            'rln':      self.req_not_implemented,
            'rrln':     self.req_not_implemented,
            'lbl':      self.req_not_implemented,
            'bps_get':  self.req_not_implemented,
            'bps_set':  self.req_not_implemented,
            'modcheck': self.req_not_implemented,
        }
    # location request, update disassembly view

    async def req_loc(self, sync):
        offset, base = sync['offset'], sync.get('base')
        await self.plugin.goto(base, offset)

    async def req_rbase(self, sync):
        self.plugin.set_remote_base(sync['rbase'])

    def req_cmt(self, sync):
        offset, base, cmt = sync['offset'], sync.get('base'), sync['msg']
        self.plugin.add_cmt(base, offset, cmt)

    def req_fcmt(self, sync):
        offset, base, cmt = sync['offset'], sync.get('base'), sync['msg']
        self.plugin.add_fcmt(base, offset, cmt)

    def req_rcmt(self, sync):
        offset, base = sync['offset'], sync.get('base')
        self.plugin.reset_cmt(base, offset)

    def req_cmd(self, sync):
        msg_b64, offset, base = sync['msg'], sync['offset'], sync['base']
        cmt = rs_decode(base64.b64decode(msg_b64))
        self.plugin.add_cmt(base, offset, cmt)

    def req_cursor(self, sync):
        cursor_addr = self.get_cursor()
        if cursor_addr:
            self.client.send(rs_encode(hex(cursor_addr)))
        else:
            rs_log('failed to get cursor location')

    def req_not_implemented(self, sync):
        rs_log(f"request type {sync['type']} not implemented")

    async def parse(self, client, sync):
        self.client = client
        stype = sync['type']
        if stype not in self.req_handlers:
            rs_log("unknown sync request: %s" % stype)
            return
        if not self.plugin.sync_enabled:
            rs_debug(
                "[-] %s request dropped because no program is enabled" % stype)
            return
        handler = self.req_handlers[stype]
        if asyncio.iscoroutinefunction(handler):
            await handler(sync)
        else:
            handler(sync)


class NoticeHandler(object):
    """Handles [notice] messages: session lifecycle events."""

    def __init__(self, plugin):
        self.plugin = plugin
        self.req_handlers = {
            'new_dbg':   self.req_new_dbg,
            'dbg_quit':  self.req_dbg_quit,
            'dbg_err':   self.req_dbg_err,
            'module':    self.req_module,
            'idb_list':  self.req_idb_list,
            'sync_mode': self.req_sync_mode,
            'idb_n':     self.req_idb_n,
            'bc':        self.req_bc,
        }

    def is_windows_dbg(self, dialect):
        return (dialect in ['windbg', 'x64_dbg', 'ollydbg2'])

    def req_new_dbg(self, notice):
        dialect = notice['dialect']
        rs_log(f"new_dbg: {notice['msg']}")
        self.plugin.bootstrap(dialect)

        if sys.platform.startswith('linux') or sys.platform == 'darwin':
            if self.is_windows_dbg(dialect):
                global RemotePath
                from pathlib import PureWindowsPath as RemotePath

    def req_dbg_quit(self, notice):
        self.plugin.reset_client()

    def req_dbg_err(self, notice):
        self.plugin.sync_enabled = False
        rs_log("dbg err: disabling current program")

    async def req_module(self, notice):
        pgm = RemotePath(notice['path']).name
        if not self.plugin.sync_mode_auto:
            rs_log(f"sync mod auto off, dropping mod request ({pgm})")
        else:
            await self.plugin.set_program(pgm)

    def req_idb_list(self, notice):
        output = "open program(s):\n"
        for i, pgm in enumerate(self.plugin.pgm_mgr.as_list()):
            is_active = ' (*)' if pgm.path.name == self.plugin.current_pgm else ''
            output += f"[{i}] {str(pgm.path.name)} {is_active}\n"

        self.plugin.broadcast(output)

    async def req_idb_n(self, notice):
        idb = notice['idb']
        try:
            idbn = int(idb)
        except (TypeError, ValueError):
            self.plugin.broadcast('> index error: n should be a decimal value')
            return

        await self.plugin.set_program_id(idbn)

    def req_sync_mode(self, notice):
        mode = notice['auto']
        rs_log(f"sync mode auto: {mode}")
        if mode == 'on':
            self.plugin.sync_mode_auto = True
        elif mode == 'off':
            self.plugin.sync_mode_auto = False
        else:
            rs_log(f"sync mode unknown: {mode}")

    def req_bc(self, notice):
        action = notice['msg']

        if action == 'on':
            self.plugin.cb_trace_enabled = True
            rs_log('color trace enabled')
        elif action == 'off':
            self.plugin.cb_trace_enabled = False
            rs_log('color trace disabled')
        elif action == 'oneshot':
            self.plugin.cb_trace_enabled = True

    async def parse(self, notice):
        ntype = notice['type']
        if ntype not in self.req_handlers:
            rs_log("unknown notice request: %s" % ntype)
            return
        handler = self.req_handlers[ntype]
        if asyncio.iscoroutinefunction(handler):
            await handler(notice)
        else:
            handler(notice)


# Directs requests to appropriate handler


class RequestType(object):
    NOTICE = '[notice]'
    SYNC = '[sync]'

    @staticmethod
    def extract(request):
        if request.startswith(RequestType.NOTICE):
            return RequestType.NOTICE
        elif request.startswith(RequestType.SYNC):
            return RequestType.SYNC
        else:
            return None

    @staticmethod
    def normalize(request, tag):
        request = request[len(tag):]
        request = request.replace("\\", "\\\\")
        request = request.replace("\n", "")
        return request.strip()


class RequestHandler(object):
    """
    Parses raw TCP strings and routes to SyncHandler or NoticeHandler.
    Uses a threading.Lock so calls from the asyncio thread and the Qt
    main thread don't interleave.
    """

    def __init__(self, plugin):
        self.plugin = plugin
        self.client_lock = threading.Lock()
        self.notice_handler = NoticeHandler(plugin)
        self.sync_handler = SyncHandler(plugin)

    async def safe_parse(self, client, request):
        with self.client_lock:
            await self.parse(client, request)

    async def parse(self, client, request):
        req_type = RequestType.extract(request)
        if not req_type:
            rs_log("unknown request type")
            return

        payload = RequestType.normalize(request, req_type)
        try:
            req_obj = json.loads(payload)
        except ValueError:
            rs_log("failed to parse request JSON\n %s\n" % payload)
            return
        rs_debug(f"REQUEST{req_type}:{req_obj['type']}")
        if req_type == RequestType.NOTICE:
            await self.notice_handler.parse(req_obj)
        elif req_type == RequestType.SYNC:
            await self.sync_handler.parse(client, req_obj)


# Networking


class ClientWriter(object):
    """
    Thin wrapper around asyncio.StreamWriter so the rest of the code can
    call client.send(bytes) just like in the asyncore version of the plugin.
    """

    def __init__(self, writer: asyncio.StreamWriter):
        self._writer = writer

    def send(self, data: bytes):
        # StreamWriter.write() buffers; drain() is called in the handler loop.
        self._writer.write(data)

    def close(self):
        self._writer.close()


class ClientListenerTask(threading.Thread):
    """
    Runs an asyncio event loop on a dedicated background thread.

    The loop hosts an asyncio TCP server. For each client connection,
    _handle_client is spawned as a task. Messages are read line by line
    and forwarded to RequestHandler (in safe_parse()).

    cmd_syncoff() calls cancel(), which schedules
    _shutdown() on the loop from the Qt thread using
    loop.call_soon_threadsafe()
    """

    def __init__(self, plugin):
        threading.Thread.__init__(self, daemon=True)
        self.plugin = plugin
        self._loop: asyncio.AbstractEventLoop = None
        self._server: asyncio.Server = None

    def cancel(self):
        """Signal the event loop to stop and wait for the thread to finish"""
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._shutdown)
        if threading.currentThread() is not self:
            self.join()

    def _shutdown(self):
        # Cancel all tasks (including the suspende _handle_client)
        for task in asyncio.all_tasks(self._loop):
            task.cancel()
        self._loop.call_soon_threadsafe(self._loop.stop)

    def set_tab_lock(self):
        """
        Called by OnViewChange (Qt main thread) to signal that a tab
        switch completed. Schedules the asyncio.Event.set() on the event
        loop thread so it's safe to await from a coroutine.
        """
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self.plugin.next_tab_lock.set)

    # Thread Entry

    def run(self):
        host = self.plugin.user_conf.host
        port = self.plugin.user_conf.port

        if not self._is_port_available(host, port):
            rs_log(f"aborting, port {
                   self.plugin.user_conf.port} already in use")
            self.plugin.client_listener = None
            return

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # The asyncio.Event used for tab-switch synchronisation must be
        # created on this loop (asyncio.Event is loop-bound in Python <3.10,
        # and implicitly uses the running loop in 3.10+).
        self.plugin.next_tab_lock = asyncio.Event()

        try:
            # Schedule the server startup coroutine, then run the loop forever.
            # cancel() will call loop.stop() which causes run_forever() to return.
            self._loop.run_until_complete(self._start_server(host, port))
            self._loop.run_forever()
        except Exception as e:
            rs_log(f"server initialization failed: {e}")
            self.plugin.client_listener = None
        finally:
            # Clean up the server and loop after run_forever() returns
            if self._server:
                self._server.close()
                self._loop.run_until_complete(self._server.wait_closed())
            self._loop.close()

    async def _start_server(self, host, port):
        self._server = await asyncio.start_server(
            self._handle_client, host, port
        )
        addr = self._server.sockets[0].getsockname()
        rs_log(f"server started on {addr}")
        self.plugin.reset_client()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        rs_log(f"incoming connection from {addr!r}")

        client = ClientWriter(writer)
        self.plugin.client = client

        try:
            while True:
                line_bytes = await reader.readline()
                if not line_bytes:
                    # OEF -> debugger disconnected
                    break
                line = rs_decode(line_bytes)
                if line.strip():
                    await self.plugin.request_handler.safe_parse(client, line)
        except asyncio.CancelledError:
            pass
        except ConnectionResetError:
            rs_log("client connection reset")
        finally:
            rs_log("client quit")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if self.plugin.client is client:
                self.plugin.client = None

    @staticmethod
    def _is_port_available(host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if sys.platform == 'win32':
                sock.setsockopt(socket.SOL_SOCKET,
                                socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((host, port))
            return True
        except Exception:
            return False
        finally:
            sock.close()


# Program tracking


@dataclass
class Program:
    path: Path
    base: int = None
    refcount: int = 1

    def lock(self):
        self.refcount += 1

    def release(self):
        self.refcount -= 1
        return (self.refcount == 0)


class ProgramManager(object):
    """
    Tracks all currently open files by basename.
    Entries are added/removed via UIContextNotification callbacks
    (OnAfterOpenFile / OnBeforeCloseFile), so no dynamic scanning needed.
    """

    def __init__(self):
        self.opened = OrderedDict()

    def add(self, file):
        ppath = Path(file)
        if ppath.name in self.opened:
            rs_log(
                f"name collision ({ppath.name}):\n"
                f"  - new:      \"{ppath}\"\n"
                f"  - existing: \"{self.opened[ppath.name].path}\""
            )
            rs_log(f"warning, tab switching may not work as expected")
            self.opened[ppath.name].lock()
        else:
            self.opened[ppath.name] = Program(ppath)

    def remove(self, file):
        pgm = Path(file).name
        if pgm in self.opened:
            if self.opened[pgm].release():
                del self.opened[pgm]

    def exists(self, pgm):
        return (Path(pgm).name in self.opened)

    def reset_bases(self):
        for pgm in self.opened.values():
            pgm.base = None

    def get_base(self, pgm):
        if self.exists(pgm):
            return self.opened[pgm].base

    def set_base(self, pgm, base):
        if self.exists(pgm):
            self.opened[pgm].base = base

    def get_at(self, index):
        keys = list(self.opened)
        return keys[index] if index < len(keys) else None

    def as_list(self):
        return self.opened.values()


# ------------------------------------------------------------------


class SyncPlugin(UIContextNotification):
    """
    Main plugin object. Inherits UIContextNotification so binja calls
    OnAfterOpenFile, OnBeforeCloseFile, and OnViewChange as the user
    opens files and switches tabs.

    It manages the asyncio server thread (ClientListenerTask), manages the
    live BinaryView/ViewFrame references updated by OnViewChange, handles
    address rebasing logic, tab-switching logic, and sending commands to the
    debugger.
    """

    def __init__(self):
        UIContextNotification.__init__(self)
        UIContext.registerNotification(self)

        self.request_handler = RequestHandler(self)
        self.client_listener: ClientListenerTask = None
        self.client: ClientWriter = None

        # Tab-switching synchronisation.
        # This starts as a plain threading.Event. Once the asyncio loop
        # starts, ClientListenerTask.run() replaces it with an asyncio.Event
        # (which must be created on the loop thread). From that point on,
        # OnViewChange calls client_listener.set_tab_lock() instead of
        # calling next_tab_lock.set() directly.
        self.next_tab_lock = threading.Event()

        self.pgm_mgr = ProgramManager()

        # Current binja UI state (updated by OnViewChange)
        self.widget = None
        self.view_frame = None
        self.view = None
        self.binary_view = None

        # Sync state
        self.current_tab = None
        self.current_pgm = None
        self.target_tab = None
        self.base = None
        self.base_remote = None
        self.sync_enabled = False
        self.sync_mode_auto = True
        self.cb_trace_enabled = False
        self.dbg_dialect = None

    def init_widget(self):
        """Create the sidebar widget. Called once on load"""
        Sidebar.addSidebarWidgetType(SyncWidgetType(self))

    # -- UIContextNotification callbacks (Qt main thread) --

    def OnAfterOpenFile(self, context, file, frame):
        self.pgm_mgr.add(file.getRawData().file.original_filename)
        return True

    def OnBeforeCloseFile(self, context, file, frame):
        filename = file.getRawData().file.original_filename
        self.pgm_mgr.remove(filename)
        if Path(filename).name == self.target_tab:
            self.target_tab = None
        return True

    def OnViewChange(self, context, frame, type):
        if frame:
            if frame != self.view_frame:
                self.view_frame = frame
                self.view = frame.getCurrentViewInterface()
                self.data = self.view.getData()
                self.binary_view = self.view_frame.actionContext().binaryView
                self.current_tab = Path(
                    self.binary_view.file.original_filename).name
                self.base = self.binary_view.start

                # Try to restore cached remote base for this file
                self.base_remote = self.pgm_mgr.get_base(self.current_tab)
                if self.base_remote:
                    rs_log(f"set remote base: {hex(self.base_remote)}")

                # If we were mid-tab-switch, check whether we've arrived
                self._notify_tab_reached()
                self.pgm_target()
            else:
                pass
                # TODO: navigate
        else:
            self.base = None
            self.base_remote = None
            self.view = None
            self.binary_view = None
            self.current_tab = None

    def _notify_tab_reached(self):
        """
        Called from OnViewChange (Qt main thread) after current_tab is updated.
        Signals the asyncio event loop that the tab switch completed.
        Uses call_soon_threadsafe so asyncio.Event.set() runs on the loop thread.
        """
        if self.client_listener and self.client_listener._loop:
            self.client_listener.set_tab_lock()

    # -- Client management --

    def bootstrap(self, dialect):
        """Called when a new debugger connects (new_dbg notice)."""
        self.pgm_mgr.reset_bases()
        self.widget.set_connected(dialect)

        if dialect in rsconfig.DBG_DIALECTS:
            self.dbg_dialect = rsconfig.DBG_DIALECTS[dialect]
            rs_log("set debugger dialect to %s, enabling hotkeys" % dialect)

    def reset_client(self):
        """Called when the debugger disconnects or the server first starts."""
        self.sync_enabled = False
        self.cb_trace_enabled = False
        self.current_pgm = None
        self.widget.reset_client()

    def broadcast(self, msg):
        self.client.send(rs_encode(msg))
        rs_log(msg)

    # -- Program / tab management --

    async def set_program(self, pgm):
        """Called when a module notice arrives and sync_mode_auto is on."""
        self.widget.set_program(pgm)
        if not self.pgm_mgr.exists(pgm):
            return
        self.sync_enabled = True
        self.current_pgm = pgm
        rs_log(f"set current program: {pgm}")
        await self.pgm_target_with_lock(pgm)

    async def set_program_id(self, index):
        """Called by idb_n notice to switch to the nth open program."""
        pgm = self.pgm_mgr.get_at(index)
        if pgm:
            self.broadcast(f"> active program is now \"{pgm}\" ({index})")
            await self.pgm_target_with_lock(pgm)
        else:
            self.broadcast(f"> idb_n error: index {
                           index} is invalid (see idblist)")

    async def pgm_target_with_lock(self, pgm=None):
        """
        Switch to the tab for pgm and BLOCK the calling coroutine until
        OnViewChange confirms the switch completed.

        This is awaited from within the asyncio event loop, so we use
        asyncio.Event (not threading.Event). The event is reset here,
        trigger_action fires the tab switch on Qt's side, and
        _notify_tab_reached() sets it via call_soon_threadsafe.

        NOTE: this method is a regular (sync) method because it is also
        called from the asyncio thread. The asyncio caller must be a
        coroutine that calls it via run_in_executor or accepts that it
        blocks — see the note in pgm_target_with_lock_async below.
        """
        self.next_tab_lock.clear()
        self.pgm_target(pgm)
        # Block this thread (the asyncio loop thread) until the Qt thread
        # fires the event. This is safe because we use call_soon_threadsafe
        # in _notify_tab_reached, which queues the .set() onto this same loop.
        # However, since we're blocking the loop thread here, no other
        # coroutines can run while we wait. For ret-sync's use case (one
        # message at a time, sequential processing) this is acceptable.
        #
        # If this becomes a problem in the future, the fix is to make
        # pgm_target_with_lock an async method and await the asyncio.Event.

        # if isinstance(self.next_tab_lock, asyncio.Event):
        #     # We're on the asyncio thread — spin-wait is wrong here.
        #     # The correct solution is to make the callers async.
        #     # For now, raise to make the problem visible rather than deadlock.
        #     raise RuntimeError(
        #         "pgm_target_with_lock called from asyncio thread with asyncio.Event — "
        #         "use pgm_target_with_lock_async instead"
        #     )
        await self.next_tab_lock.wait()

    def pgm_target(self, pgm=None):
        """
        Queue a 'Next Tab' action if we're not already on the right tab.
        Called from the asyncio thread, but trigger_action posts to Qt
        via UIContext which is thread-safe.
        """
        if pgm:
            self.target_tab = pgm
        if not self.target_tab:
            return
        try:
            if self.target_tab != self.current_tab:
                self.trigger_action("Next Tab")
            else:
                self.target_tab = None
                # If we're already on the right tab, signal immediately
                if isinstance(self.next_tab_lock, asyncio.Event):
                    if self.client_listener and self.client_listener._loop:
                        self.client_listener._loop.call_soon_threadsafe(
                            self.next_tab_lock.set
                        )
                else:
                    self.next_tab_lock.set()
        except Exception as e:
            rs_log(f"error while switching tabs: {e}")

    async def restore_tab(self):
        if self.current_tab == self.current_pgm:
            return True
        if not self.pgm_mgr.exists(self.current_pgm):
            return False
        await self.pgm_target_with_lock(self.current_pgm)
        return True

    def trigger_action(self, action: str):
        """Execute a UI action (e.g. 'Next Tab') on the main window."""
        ctx = UIContext.activeContext()
        if ctx:
            handler = ctx.contentActionHandler()
            handler.executeAction(action)

    # -- Address rebasing --

    # check if address is within a valid segment
    def is_safe(self, offset):
        return self.binary_view.is_valid_offset(offset)

    def rebase(self, base, offset):
        """Translate a remote (debugger) address to a local Binja address."""
        if base is not None:
            if base > offset:
                rs_log('unsafe addr: 0x%x > 0x%x' % (base, offset))
                return None
            if self.base_remote != base:
                self.pgm_mgr.set_base(self.current_tab, base)
                self.base_remote = base
            dest = self.rebase_local(offset)
        else:
            dest = offset

        if not self.is_safe(dest):
            rs_log('unsafe addr: 0x%x not in valid segment' % dest)
            return None
        return dest

    def rebase_local(self, offset):
        """remote offset -> local offset"""
        if not (self.base == self.base_remote):
            offset = (offset - self.base_remote) + self.base

        return offset

    def rebase_remote(self, offset):
        """local offset -> remote offset"""
        if not (self.base == self.base_remote):
            offset = (offset - self.base) + self.base_remote

        return offset

    def set_remote_base(self, rbase):
        self.pgm_mgr.set_base(self.current_tab, rbase)
        self.base_remote = rbase

    # -- Navigation --

    async def goto(self, base, offset):
        if not self.sync_enabled:
            return
        if await self.restore_tab():
            goto_addr = self.rebase(base, offset)
            if goto_addr is None:
                return
            view = self.binary_view.view
            if not self.binary_view.navigate(view, goto_addr):
                rs_log(f"goto {hex(goto_addr)} error")
            if self.cb_trace_enabled:
                self.color_callback(goto_addr)
        else:
            rs_log('goto: no view available')

    def color_callback(self, hglt_addr):
        blocks = self.binary_view.get_basic_blocks_at(hglt_addr)
        for block in blocks:
            block.function.set_user_instr_highlight(
                hglt_addr, rsconfig.CB_TRACE_COLOR)

    def get_cursor(self):
        if not self.view_frame:
            return None
        offset = self.view_frame.getCurrentOffset()
        return self.rebase_remote(offset)

    def add_cmt(self, base, offset, cmt):
        cmt_addr = self.rebase(base, offset)
        if cmt_addr:
            in_place = self.binary_view.get_comment_at(cmt_addr)
            if in_place:
                cmt = f"{in_place}\n{cmt}"

            self.binary_view.set_comment_at(cmt_addr, cmt)

    def reset_cmt(self, base, offset):
        cmt_addr = self.rebase(base, offset)
        if cmt_addr:
            self.binary_view.set_comment_at(cmt_addr, '')

    def add_fcmt(self, base, offset, cmt):
        if not self.binary_view:
            return
        cmt_addr = self.rebase(base, offset)
        for fn in self.binary_view.get_functions_containing(cmt_addr):
            fn.comment = cmt

    # -- Debugger Commands --

    def commands_available(self):
        if (self.sync_enabled and self.dbg_dialect):
            return True
        rs_log('commands not available')
        return False

    def send_cmd(self, cmd, args, oneshot=False):
        if not self.commands_available():
            return
        if cmd not in self.dbg_dialect:
            rs_log(f"{cmd}: unknown command in dialect")
            return
        cmdline = self.dbg_dialect[cmd]
        if args and args != '':
            cmdline += args
        if oneshot and 'oneshot_post' in self.dbg_dialect:
            cmdline += self.dbg_dialect['oneshot_post']
        self.client.send(rs_encode(cmdline))

    def send_cmd_raw(self, cmd, args,):
        if not self.commands_available():
            return
        cmd_pre = self.dbg_dialect.get('prefix', '')
        cmdline = f"{cmd_pre}{cmd} {args}"
        self.client.send(rs_encode(cmdline))

    def send_simple_cmd(self, cmd):
        self.send_cmd(cmd, '')

    def generic_bp(self, bp_cmd, oneshot=False):
        ui_addr = self.view_frame.getCurrentOffset()
        if not ui_addr:
            rs_log('failed to get cursor location')
            return
        if not self.base_remote:
            rs_log(f"{bp_cmd} failed, remote base of {
                   self.current_pgm} program unknown")
            return
        remote_addr = self.rebase_remote(ui_addr)
        self.send_cmd(bp_cmd, hex(remote_addr), oneshot)

    # -- Hotkey Commands --

    def cmd_go(self, ctx=None):       self.send_simple_cmd('go')
    def cmd_si(self, ctx=None):       self.send_simple_cmd('si')
    def cmd_so(self, ctx=None):       self.send_simple_cmd('so')
    def cmd_bp(self, ctx=None):       self.generic_bp('bp')
    def cmd_hwbp(self, ctx=None):     self.generic_bp('hbp')
    def cmd_bp1(self, ctx=None):      self.generic_bp('bp1', True)
    def cmd_hwbp1(self, ctx=None):    self.generic_bp('hbp1', True)

    def cmd_translate(self, ctx=None):
        ui_addr = self.view_frame.getCurrentOffset()
        if not ui_addr:
            rs_log('failed to get cursor location')
            return
        rs_debug(f"translate address {hex(ui_addr)}")
        args = f"{hex(self.base)} {hex(ui_addr)} {self.current_pgm}"
        self.send_cmd_raw("translate", args)

    def cmd_sync(self, ctx=None):
        if not self.pgm_mgr.opened:
            rs_log('please open a tab first')
            return
        if self.client_listener:
            rs_log('already listening')
            return
        if self.widget is None:
            rs_log('please open the ret-sync sidebar panel first')
            return
        local_path = str(self.pgm_mgr.opened[self.current_tab].path)
        self.user_conf = load_configuration(local_path)
        self.client_listener = ClientListenerTask(self)
        self.client_listener.start()

    def cmd_syncoff(self, ctx=None):
        if self.client_listener:
            self.client_listener.cancel()
            self.client_listener = None
            self.widget.reset_status()
        else:
            rs_log('not listening')
