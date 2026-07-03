#!/usr/bin/env python3
import sys
from unittest.mock import MagicMock

import dns

import os

for mod in [
    'pylsqpack',
    'aioquic', 'aioquic.h3', 'aioquic.h3.connection', 'aioquic.h3.events',
    'aioquic.quic', 'aioquic.quic.configuration', 'aioquic.quic.connection', 'aioquic.quic.events',
    'dns.quic', 'dns.quic._asyncio', 'dns.quic._common', 'dns.quic._sync',
]:
    sys.modules[mod] = MagicMock()
dns.quic = sys.modules['dns.quic']

import json
import logging
import os
import time

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView

def get_shared_dir() -> str:
    try:
        from android.storage import app_storage_path
        return app_storage_path()
    except ImportError:
        return '/tmp'  # Fallback für Desktop

STATUS_FILE = os.path.join(get_shared_dir(), 'dpyproxy_status.json')
STOP_FILE   = os.path.join(get_shared_dir(), 'dpyproxy_stop')


class KivyLogHandler(logging.Handler):
    def __init__(self, label: Label, scroll_view: ScrollView):
        super().__init__()
        self.label = label
        self.scroll_view = scroll_view

    def emit(self, record):
        msg = self.format(record)
        Clock.schedule_once(lambda dt: self._append(msg))

    def _append(self, msg):
        self.label.text += f"\n{msg}"
        self.scroll_view.scroll_y = 0


class DPYProxyApp(App):
    def build(self):
        self._service = None
        self._last_log = ''
        self._last_ts = 0.0

        root = BoxLayout(
            orientation='vertical',
            padding=(10, Window.top + 10, 10, 10),
            spacing=10,
        )

        self.scroll_view = ScrollView(size_hint=(1, 0.85))
        self.log_label = Label(
            text="[Ready]",
            size_hint_y=None,
            size_hint_x=1,
            halign='left',
            valign='top',
            font_size='12sp',
            padding=(8, 8),
        )
        self.log_label.bind(
            width=lambda *a: self.log_label.setter('text_size')(
                self.log_label, (self.log_label.width, None)
            ),
            texture_size=lambda *a: self.log_label.setter('size')(
                self.log_label, self.log_label.texture_size
            ),
        )
        self.scroll_view.add_widget(self.log_label)
        root.add_widget(self.scroll_view)

        btn_row = BoxLayout(size_hint=(1, 0.15), spacing=10)
        self.start_btn = Button(text='Start', background_color=(0.2, 0.8, 0.2, 1))
        self.stop_btn  = Button(text='Stop',  background_color=(0.8, 0.2, 0.2, 1), disabled=True)
        self.start_btn.bind(on_press=self.start_service)
        self.stop_btn.bind(on_press=self.stop_service)
        btn_row.add_widget(self.start_btn)
        btn_row.add_widget(self.stop_btn)
        root.add_widget(btn_row)

        handler = KivyLogHandler(self.log_label, self.scroll_view)
        handler.setFormatter(logging.Formatter('[%(levelname)s] %(name)s: %(message)s'))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

        # Poll status file every second
        Clock.schedule_interval(self._poll_status, 1.0)

        return root

    def start_service(self, instance):
        try:
            from jnius import autoclass
            service = autoclass('de.upb.syssec.dpyproxy.ServiceDpyproxyservice')
            mActivity = autoclass('org.kivy.android.PythonActivity').mActivity
            argument = ''
            service.start(mActivity, argument)

        except Exception as e:
            logging.error(f"Service start error: {e}")
            return

        self.start_btn.disabled = True
        self.stop_btn.disabled = False
        self.log_label.text = "[Starting service...]"
        logging.info("Service gestartet!")

    def stop_service(self, instance):
        with open(STOP_FILE, 'w') as f:
            f.write('stop')

        try:
            from jnius import autoclass, cast
            
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            Intent = autoclass('android.content.Intent')
            context = PythonActivity.mActivity
            
            service_class = autoclass('de.upb.syssec.dpyproxy.ServiceDpyproxyservice')
            intent = Intent(context, service_class)
            context.stopService(intent)
            
        except Exception as e:
            logging.warning(f"Service stop error: {e}")

        self._reset_buttons()
        logging.info("Stop-Signal gesendet.")

    def _poll_status(self, dt):
        """Read status file written by service and update UI."""
        try:
            if not os.path.exists(STATUS_FILE):
                return
            with open(STATUS_FILE) as f:
                data = json.load(f)

            ts  = data.get('ts', 0.0)
            log = data.get('log', '')

            # Only update if something changed
            if ts != self._last_ts:
                self._last_ts = ts
                if log != self._last_log:
                    new_text = log[len(self._last_log):]
                    if new_text.strip():
                        self.log_label.text += new_text
                        self.scroll_view.scroll_y = 0
                    self._last_log = log

            status = data.get('status', '')
            if status in ('stopped', 'error'):
                self._reset_buttons()

        except Exception:
            pass

    def _reset_buttons(self):
        self.start_btn.disabled = False
        self.stop_btn.disabled = True


if __name__ == '__main__':
    DPYProxyApp().run()
