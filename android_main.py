#!/usr/bin/env python3
import sys
from unittest.mock import MagicMock

import dns

for mod in [
    "pylsqpack",
    "aioquic",
    "aioquic.h3",
    "aioquic.h3.connection",
    "aioquic.h3.events",
    "aioquic.quic",
    "aioquic.quic.configuration",
    "aioquic.quic.connection",
    "aioquic.quic.events",
    "dns.quic",
    "dns.quic._asyncio",
    "dns.quic._common",
    "dns.quic._sync",
]:
    sys.modules[mod] = MagicMock()
dns.quic = sys.modules["dns.quic"]

import json
import logging
import os

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics import Color, Ellipse, RoundedRectangle
from kivy.metrics import dp
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.switch import Switch
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget

from enumerators.DnsProxyMode import DnsProxyMode

# ---------------------------------------------------------------- storage --


def get_shared_dir() -> str:
    try:
        from android.storage import app_storage_path

        return app_storage_path()
    except ImportError:
        return "/tmp"  # fallback for desktop


STATUS_FILE = os.path.join(get_shared_dir(), "dpyproxy_status.json")
STOP_FILE = os.path.join(get_shared_dir(), "dpyproxy_stop")
CONFIG_FILE = os.path.join(get_shared_dir(), "dpyproxy_config.json")

CONFIG_DEFAULTS = {
    "tls_port": 4433,
    "tls_timeout": 10,
    "tls_record_frag": True,
    "tls_tcp_frag": True,
    "tls_frag_size": 100,
    "dns_port": 5533,
    "dns_mode": DnsProxyMode.AUTO.name,
    "dns_timeout": 3,
}


def load_config() -> dict:
    try:
        with open(CONFIG_FILE) as f:
            return {**CONFIG_DEFAULTS, **json.load(f)}
    except Exception:
        return dict(CONFIG_DEFAULTS)


def save_config(cfg: dict):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


def get_inset_px(dimen_name: str, fallback: float) -> float:
    """Reads an Android system inset (status/navigation bar height) in real pixels."""
    try:
        from jnius import autoclass

        activity = autoclass("org.kivy.android.PythonActivity").mActivity
        resources = activity.getResources()
        resource_id = resources.getIdentifier(dimen_name, "dimen", "android")
        if resource_id > 0:
            return float(resources.getDimensionPixelSize(resource_id))
    except Exception:
        pass
    return fallback


# ------------------------------------------------------------------ theme --

BG = (0.07, 0.09, 0.12, 1)
CARD = (0.12, 0.15, 0.19, 1)
FIELD = (0.16, 0.19, 0.24, 1)
TEXT = (0.93, 0.95, 0.97, 1)
TEXT_DIM = (0.58, 0.64, 0.70, 1)
GREEN = (0.22, 0.78, 0.42, 1)
RED = (0.87, 0.29, 0.29, 1)
AMBER = (0.93, 0.69, 0.13, 1)

# Colors for the Android settings mockup — deliberately a light Material-ish
# palette (unlike the app's own dark theme) so it reads as "a screenshot of
# something else", the way a real phone screenshot would look pasted in.
PHONE_BEZEL = (0.03, 0.04, 0.05, 1)
SCREEN_BG = (0.97, 0.97, 0.98, 1)
SCREEN_FIELD = (0.91, 0.92, 0.94, 1)
SCREEN_TEXT = (0.11, 0.12, 0.13, 1)
SCREEN_TEXT_DIM = (0.44, 0.47, 0.50, 1)
ANDROID_BLUE = (0.10, 0.45, 0.91, 1)


class Card(BoxLayout):
    def __init__(self, bg_color=CARD, radius=12, **kwargs):
        kwargs.setdefault("orientation", "vertical")
        kwargs.setdefault("padding", (dp(14), dp(12)))
        kwargs.setdefault("spacing", dp(8))
        kwargs.setdefault("size_hint_y", None)
        super().__init__(**kwargs)
        self.bind(minimum_height=self.setter("height"))
        with self.canvas.before:
            Color(*bg_color)
            self._bg = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(radius)])
        self.bind(pos=self._update_bg, size=self._update_bg)

    def _update_bg(self, *_a):
        self._bg.pos = self.pos
        self._bg.size = self.size


class RoundedButton(Button):
    def __init__(self, bg_color=GREEN, **kwargs):
        super().__init__(**kwargs)
        self.background_normal = ""
        self.background_down = ""
        self.background_color = (0, 0, 0, 0)
        self.color = TEXT
        self.bold = True
        self.font_size = "15sp"
        self._base_color = bg_color
        with self.canvas.before:
            self._color = Color(*bg_color)
            self._rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(10)])
        self.bind(pos=self._update, size=self._update, disabled=self._update)

    def _update(self, *_a):
        self._rect.pos = self.pos
        self._rect.size = self.size
        r, g, b, _a2 = self._base_color
        self._color.rgba = (r, g, b, 0.35 if self.disabled else 1)


class StatusDot(Widget):
    def __init__(self, color=TEXT_DIM, **kwargs):
        kwargs.setdefault("size_hint", (None, None))
        kwargs.setdefault("size", (dp(10), dp(10)))
        super().__init__(**kwargs)
        with self.canvas:
            self._color = Color(*color)
            self._ellipse = Ellipse(pos=self.pos, size=self.size)
        self.bind(pos=self._update, size=self._update)

    def _update(self, *_a):
        self._ellipse.pos = self.pos
        self._ellipse.size = self.size

    def set_color(self, color):
        self._color.rgba = color


class NumberBadge(BoxLayout):
    """A small filled circle with a number in it, used for step indicators."""

    def __init__(self, number: int, **kwargs):
        kwargs.setdefault("size_hint", (None, None))
        kwargs.setdefault("size", (dp(26), dp(26)))
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(*GREEN)
            self._circle = Ellipse(pos=self.pos, size=self.size)
        self.bind(pos=self._update, size=self._update)
        label = Label(text=str(number), bold=True, font_size="13sp", color=BG)
        self.add_widget(label)

    def _update(self, *_a):
        self._circle.pos = self.pos
        self._circle.size = self.size


def step_row(number: int, title: str, body: str) -> BoxLayout:
    row = BoxLayout(orientation="horizontal", size_hint_y=None, spacing=dp(12), padding=(0, dp(2)))
    badge_holder = AnchorLayout(anchor_y="top", size_hint=(None, 1), width=dp(26))
    badge_holder.add_widget(NumberBadge(number))
    row.add_widget(badge_holder)

    text_box = BoxLayout(orientation="vertical", spacing=dp(2))
    title_lbl = Label(
        text=title,
        bold=True,
        font_size="14sp",
        color=TEXT,
        halign="left",
        valign="top",
        size_hint_y=None,
    )
    title_lbl.bind(width=lambda *_a: title_lbl.setter("text_size")(title_lbl, (title_lbl.width, None)))
    title_lbl.bind(texture_size=lambda *_a: title_lbl.setter("height")(title_lbl, title_lbl.texture_size[1]))
    body_lbl = Label(
        text=body,
        font_size="13sp",
        color=TEXT_DIM,
        halign="left",
        valign="top",
        size_hint_y=None,
    )
    body_lbl.bind(width=lambda *_a: body_lbl.setter("text_size")(body_lbl, (body_lbl.width, None)))
    body_lbl.bind(texture_size=lambda *_a: body_lbl.setter("height")(body_lbl, body_lbl.texture_size[1]))
    text_box.add_widget(title_lbl)
    text_box.add_widget(body_lbl)
    text_box.bind(minimum_height=text_box.setter("height"))
    row.add_widget(text_box)

    row.bind(minimum_height=row.setter("height"))
    text_box.size_hint_y = None
    return row


def info_box(text: str, accent=ANDROID_BLUE) -> BoxLayout:
    """A callout card with a colored left accent bar, for tips/warnings."""
    outer = BoxLayout(orientation="horizontal", size_hint_y=None, spacing=0)
    bar = Widget(size_hint=(None, 1), width=dp(3))
    with bar.canvas:
        Color(*accent)
        bar_rect = RoundedRectangle(pos=bar.pos, size=bar.size, radius=[dp(1.5)])
    bar.bind(pos=lambda *_a: setattr(bar_rect, "pos", bar.pos), size=lambda *_a: setattr(bar_rect, "size", bar.size))

    card = Card(bg_color=FIELD, padding=(dp(12), dp(10)))
    lbl = Label(
        text=text,
        font_size="12sp",
        color=TEXT_DIM,
        halign="left",
        valign="top",
        size_hint_y=None,
    )
    lbl.bind(width=lambda *_a: lbl.setter("text_size")(lbl, (lbl.width, None)))
    lbl.bind(texture_size=lambda *_a: lbl.setter("height")(lbl, lbl.texture_size[1]))
    card.add_widget(lbl)

    outer.add_widget(bar)
    outer.add_widget(card)
    outer.bind(minimum_height=outer.setter("height"))
    card.size_hint_x = 1
    return outer


def phone_field(label_text: str, value_text: str, value_color=SCREEN_TEXT) -> BoxLayout:
    """One labeled row inside the phone mockup, styled like an Android settings field."""
    row = BoxLayout(orientation="vertical", size_hint_y=None, height=dp(46), spacing=dp(2))
    lbl = Label(
        text=label_text,
        font_size="10sp",
        color=SCREEN_TEXT_DIM,
        halign="left",
        valign="bottom",
        size_hint_y=None,
        height=dp(14),
    )
    lbl.bind(size=lbl.setter("text_size"))
    val = Label(
        text=value_text,
        font_size="14sp",
        color=value_color,
        bold=True,
        halign="left",
        valign="top",
        size_hint_y=None,
        height=dp(20),
    )
    val.bind(size=val.setter("text_size"))
    row.add_widget(lbl)
    row.add_widget(val)
    return row


def build_phone_mockup(proxy_host: str, proxy_port: str) -> Widget:
    """A stylized mockup of Android's Wi-Fi 'Edit network' proxy dialog."""
    bezel = Card(bg_color=PHONE_BEZEL, radius=22, padding=(dp(8), dp(8)), spacing=0)
    bezel.size_hint_x = 1

    screen = Card(bg_color=SCREEN_BG, radius=14, padding=(dp(14), dp(12)), spacing=dp(10))
    screen.size_hint_x = 1

    header = Label(
        text="Edit network",
        bold=True,
        font_size="15sp",
        color=SCREEN_TEXT,
        halign="left",
        valign="middle",
        size_hint_y=None,
        height=dp(22),
    )
    header.bind(size=header.setter("text_size"))
    screen.add_widget(header)

    proxy_toggle_row = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(40))
    proxy_toggle_lbl = Label(
        text="Proxy",
        font_size="13sp",
        color=SCREEN_TEXT,
        halign="left",
        valign="middle",
        size_hint_x=0.5,
    )
    proxy_toggle_lbl.bind(size=proxy_toggle_lbl.setter("text_size"))
    manual_pill = Card(bg_color=ANDROID_BLUE, radius=14, padding=(dp(12), dp(6)))
    manual_pill.size_hint = (None, None)
    manual_pill.size = (dp(80), dp(28))
    manual_pill.add_widget(Label(text="Manual", font_size="12sp", bold=True, color=(1, 1, 1, 1)))
    pill_anchor = AnchorLayout(anchor_x="right", size_hint_x=0.5)
    pill_anchor.add_widget(manual_pill)
    proxy_toggle_row.add_widget(proxy_toggle_lbl)
    proxy_toggle_row.add_widget(pill_anchor)
    screen.add_widget(proxy_toggle_row)

    screen.add_widget(phone_field("Proxy hostname", proxy_host, ANDROID_BLUE))
    screen.add_widget(phone_field("Proxy port", proxy_port, ANDROID_BLUE))

    save_row = AnchorLayout(anchor_x="right", size_hint_y=None, height=dp(30))
    save_row.add_widget(
        Label(
            text="SAVE",
            bold=True,
            font_size="13sp",
            color=ANDROID_BLUE,
            size_hint=(None, None),
            size=(dp(60), dp(24)),
        )
    )
    screen.add_widget(save_row)

    bezel.add_widget(screen)
    return bezel


def section_label(text: str) -> Label:
    lbl = Label(
        text=text.upper(),
        color=GREEN,
        bold=True,
        font_size="12sp",
        size_hint_y=None,
        height=dp(20),
        halign="left",
        valign="middle",
    )
    lbl.bind(size=lbl.setter("text_size"))
    return lbl


def field_row(label_text: str, widget) -> BoxLayout:
    row = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(46), spacing=dp(10))
    lbl = Label(
        text=label_text,
        color=TEXT,
        font_size="14sp",
        halign="left",
        valign="middle",
        size_hint_x=0.55,
    )
    lbl.bind(size=lbl.setter("text_size"))
    row.add_widget(lbl)
    widget.size_hint_x = 0.45
    row.add_widget(widget)
    return row


def styled_text_input(text: str) -> TextInput:
    ti = TextInput(
        text=text,
        multiline=False,
        input_filter="int",
        background_normal="",
        background_active="",
        background_color=FIELD,
        foreground_color=TEXT,
        cursor_color=GREEN,
        hint_text_color=TEXT_DIM,
        padding=(dp(10), dp(10)),
        font_size="14sp",
        size_hint_y=None,
        height=dp(40),
    )
    return ti


def styled_spinner(text: str, values) -> Spinner:
    sp = Spinner(
        text=text,
        values=values,
        background_normal="",
        background_color=FIELD,
        color=TEXT,
        font_size="13sp",
        size_hint_y=None,
        height=dp(40),
    )
    return sp


# ------------------------------------------------------------------- app --


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
        Window.clearcolor = BG

        self._last_log = ""
        self._last_ts = 0.0
        self._config_widgets = []

        top_inset = get_inset_px("status_bar_height", dp(24))
        bottom_inset = get_inset_px("navigation_bar_height", 0)

        root = BoxLayout(
            orientation="vertical",
            padding=(dp(14), top_inset + dp(10), dp(14), bottom_inset + dp(12)),
            spacing=dp(10),
        )

        root.add_widget(self._build_header())

        tabs = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        self.tab_log_btn = self._make_tab_button("Log", active=True)
        self.tab_settings_btn = self._make_tab_button("Settings", active=False)
        self.tab_guide_btn = self._make_tab_button("Setup Guide", active=False)
        self.tab_log_btn.bind(on_press=lambda *_: self._show_tab("log"))
        self.tab_settings_btn.bind(on_press=lambda *_: self._show_tab("settings"))
        self.tab_guide_btn.bind(on_press=lambda *_: self._show_tab("guide"))
        tabs.add_widget(self.tab_log_btn)
        tabs.add_widget(self.tab_settings_btn)
        tabs.add_widget(self.tab_guide_btn)
        root.add_widget(tabs)

        self.content_area = BoxLayout(size_hint_y=1)
        root.add_widget(self.content_area)

        self._log_panel = self._build_log_panel()
        self._settings_panel = self._build_settings_panel()
        self._guide_panel = self._build_guide_panel()
        self._show_tab("log")

        root.add_widget(self._build_button_row())

        handler = KivyLogHandler(self.log_label, self.scroll_view)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

        # Clean up stop flag from previous run
        if os.path.exists(STATUS_FILE):
            os.remove(STATUS_FILE)

        Clock.schedule_interval(self._poll_status, 1.0)

        return root

    # -- layout builders ---------------------------------------------------

    def _build_header(self):
        header = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))
        title_box = BoxLayout(orientation="vertical")
        title = Label(
            text="DPYProxy",
            bold=True,
            font_size="20sp",
            color=TEXT,
            halign="left",
            valign="middle",
            size_hint_y=None,
            height=dp(26),
        )
        title.bind(size=title.setter("text_size"))
        subtitle = Label(
            text="DPI circumvention proxy",
            font_size="11sp",
            color=TEXT_DIM,
            halign="left",
            valign="top",
            size_hint_y=None,
            height=dp(14),
        )
        subtitle.bind(size=subtitle.setter("text_size"))
        title_box.add_widget(title)
        title_box.add_widget(subtitle)
        header.add_widget(title_box)

        status_anchor = AnchorLayout(anchor_x="right", anchor_y="center", size_hint_x=None, width=dp(120))
        status_box = BoxLayout(
            orientation="horizontal",
            size_hint=(None, None),
            height=dp(20),
            spacing=dp(6),
        )
        status_box.bind(minimum_width=status_box.setter("width"))

        # BoxLayout re-asserts its children's positions on every layout pass,
        # so a fixed-size child like the dot can't just be bound to a
        # center_y — it needs its own AnchorLayout cell to be centered in.
        dot_holder = AnchorLayout(anchor_y="center", size_hint=(None, 1), width=dp(10))
        self.status_dot = StatusDot(color=TEXT_DIM)
        dot_holder.add_widget(self.status_dot)

        self.status_label = Label(
            text="Stopped",
            color=TEXT_DIM,
            bold=True,
            font_size="13sp",
            size_hint_x=None,
            halign="left",
            valign="middle",
        )
        self.status_label.bind(
            texture_size=lambda *_a: setattr(self.status_label, "width", self.status_label.texture_size[0])
        )
        status_box.add_widget(dot_holder)
        status_box.add_widget(self.status_label)
        status_anchor.add_widget(status_box)
        header.add_widget(status_anchor)

        return header

    def _make_tab_button(self, text, active):
        btn = RoundedButton(
            text=text,
            bg_color=CARD if not active else FIELD,
            size_hint_y=1,
        )
        return btn

    def _show_tab(self, which: str):
        self.content_area.clear_widgets()
        panels = {"log": self._log_panel, "settings": self._settings_panel, "guide": self._guide_panel}
        buttons = {"log": self.tab_log_btn, "settings": self.tab_settings_btn, "guide": self.tab_guide_btn}
        self.content_area.add_widget(panels[which])
        for key, btn in buttons.items():
            btn._base_color = FIELD if key == which else CARD
            btn._update()

    def _build_log_panel(self):
        card = Card(size_hint_y=1, padding=(dp(2), dp(2)))
        self.scroll_view = ScrollView()
        self.log_label = Label(
            text="[Ready]",
            size_hint_y=None,
            size_hint_x=1,
            halign="left",
            valign="top",
            font_size="12sp",
            color=TEXT,
            padding=(dp(10), dp(10)),
        )
        self.log_label.bind(
            width=lambda *a: self.log_label.setter("text_size")(self.log_label, (self.log_label.width, None)),
            texture_size=lambda *a: self.log_label.setter("size")(self.log_label, self.log_label.texture_size),
        )
        self.scroll_view.add_widget(self.log_label)
        card.add_widget(self.scroll_view)
        return card

    def _build_settings_panel(self):
        cfg = load_config()

        outer = ScrollView(size_hint_y=1)
        content = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(12))
        content.bind(minimum_height=content.setter("height"))

        hint = Label(
            text="Changes apply on the next Start. Fields lock while running.",
            font_size="11sp",
            color=TEXT_DIM,
            size_hint_y=None,
            height=dp(28),
            halign="left",
            valign="middle",
        )
        hint.bind(size=hint.setter("text_size"))
        content.add_widget(hint)

        tls_card = Card()
        tls_card.add_widget(section_label("TLS Proxy"))

        self.f_tls_port = styled_text_input(str(cfg["tls_port"]))
        tls_card.add_widget(field_row("Port", self.f_tls_port))

        self.f_tls_timeout = styled_text_input(str(cfg["tls_timeout"]))
        tls_card.add_widget(field_row("Timeout (s)", self.f_tls_timeout))

        self.f_tls_record_frag = Switch(active=cfg["tls_record_frag"], size_hint_y=None, height=dp(40))
        tls_card.add_widget(field_row("Record fragmentation", self.f_tls_record_frag))

        self.f_tls_tcp_frag = Switch(active=cfg["tls_tcp_frag"], size_hint_y=None, height=dp(40))
        tls_card.add_widget(field_row("TCP fragmentation", self.f_tls_tcp_frag))

        self.f_tls_frag_size = styled_text_input(str(cfg["tls_frag_size"]))
        tls_card.add_widget(field_row("Fragment size (bytes)", self.f_tls_frag_size))

        content.add_widget(tls_card)

        dns_card = Card()
        dns_card.add_widget(section_label("DNS Proxy"))

        self.f_dns_port = styled_text_input(str(cfg["dns_port"]))
        dns_card.add_widget(field_row("Port", self.f_dns_port))

        self.f_dns_mode = styled_spinner(cfg["dns_mode"], [m.name for m in DnsProxyMode])
        dns_card.add_widget(field_row("Mode", self.f_dns_mode))

        self.f_dns_timeout = styled_text_input(str(cfg["dns_timeout"]))
        dns_card.add_widget(field_row("Timeout (s)", self.f_dns_timeout))

        content.add_widget(dns_card)

        self._config_widgets = [
            self.f_tls_port,
            self.f_tls_timeout,
            self.f_tls_record_frag,
            self.f_tls_tcp_frag,
            self.f_tls_frag_size,
            self.f_dns_port,
            self.f_dns_mode,
            self.f_dns_timeout,
        ]

        outer.add_widget(content)
        return outer

    def _build_guide_panel(self):
        cfg = load_config()

        outer = ScrollView(size_hint_y=1)
        content = BoxLayout(orientation="vertical", size_hint_y=None, spacing=dp(14))
        content.bind(minimum_height=content.setter("height"))

        intro = Label(
            text=(
                "DPYProxy only sees traffic that Android sends it. Configure it as your "
                "Wi-Fi network's proxy so apps route their HTTP(S) traffic through it."
            ),
            font_size="12sp",
            color=TEXT_DIM,
            size_hint_y=None,
            halign="left",
            valign="top",
        )
        intro.bind(width=lambda *_a: intro.setter("text_size")(intro, (intro.width, None)))
        intro.bind(texture_size=lambda *_a: intro.setter("height")(intro, intro.texture_size[1]))
        content.add_widget(intro)

        steps_card = Card(spacing=dp(14))
        steps_card.add_widget(section_label("Step-by-step"))
        steps_card.add_widget(
            step_row(
                1,
                "Start the proxy",
                "Open the Log tab and tap Start. Wait for the status at the top to show Running.",
            )
        )
        steps_card.add_widget(
            step_row(
                2,
                "Open Wi-Fi settings",
                "On your device: Settings -> Network & internet -> Wi-Fi (Samsung: Settings -> Connections -> Wi-Fi).",
            )
        )
        steps_card.add_widget(
            step_row(
                3,
                "Edit your network",
                "Tap the gear icon next to the Wi-Fi network you are connected to, "
                'or long-press it, then choose "Modify network".',
            )
        )
        steps_card.add_widget(
            step_row(
                4,
                "Expand advanced options",
                'Tap "Advanced options" (or the small arrow) to reveal the Proxy setting.',
            )
        )
        steps_card.add_widget(
            step_row(
                5,
                "Set the proxy to Manual",
                "Change Proxy from None to Manual, then fill in the hostname and port shown below:",
            )
        )

        mockup = build_phone_mockup("127.0.0.1", str(cfg["tls_port"]))
        mockup_wrap = AnchorLayout(size_hint_y=None, padding=(dp(20), 0))
        mockup_wrap.add_widget(mockup)
        # The mockup's real height depends on font metrics, which vary by
        # device DPI — a fixed guess here overflowed into the text above it
        # on some screens. Track the actual (Card-computed) height instead.
        mockup.bind(height=lambda _inst, val, wrap=mockup_wrap: setattr(wrap, "height", val))
        steps_card.add_widget(mockup_wrap)

        steps_card.add_widget(
            step_row(
                6,
                "Save",
                "Tap Save. Apps that use the system proxy will now route their traffic through DPYProxy.",
            )
        )
        content.add_widget(steps_card)

        content.add_widget(
            info_box(
                f"Hostname and port always match the TLS Proxy settings on the Settings tab "
                f"(currently port {cfg['tls_port']}). If you change the port there, update it here too.",
                accent=ANDROID_BLUE,
            )
        )
        content.add_widget(
            info_box(
                "Menu names vary slightly by Android version and manufacturer, but the "
                "Proxy hostname / Proxy port fields work the same way on every device.",
                accent=GREEN,
            )
        )
        content.add_widget(
            info_box(
                "Only apps that respect the system proxy setting are covered this way — some "
                "apps use raw sockets and bypass it entirely. See the README for details.",
                accent=AMBER,
            )
        )

        outer.add_widget(content)
        return outer

    def _build_button_row(self):
        btn_row = BoxLayout(size_hint_y=None, height=dp(52), spacing=dp(10))
        self.start_btn = RoundedButton(text="Start", bg_color=GREEN)
        self.stop_btn = RoundedButton(text="Stop", bg_color=RED, disabled=True)
        self.start_btn.bind(on_press=self.start_service)
        self.stop_btn.bind(on_press=self.stop_service)
        btn_row.add_widget(self.start_btn)
        btn_row.add_widget(self.stop_btn)
        return btn_row

    # -- config -------------------------------------------------------------

    def _gather_config(self):
        try:
            return {
                "tls_port": int(self.f_tls_port.text),
                "tls_timeout": int(self.f_tls_timeout.text),
                "tls_record_frag": self.f_tls_record_frag.active,
                "tls_tcp_frag": self.f_tls_tcp_frag.active,
                "tls_frag_size": int(self.f_tls_frag_size.text),
                "dns_port": int(self.f_dns_port.text),
                "dns_mode": self.f_dns_mode.text,
                "dns_timeout": int(self.f_dns_timeout.text),
            }
        except ValueError:
            return None

    def _set_config_locked(self, locked: bool):
        for widget in self._config_widgets:
            widget.disabled = locked

    # -- service control ------------------------------------------------

    def start_service(self, instance):
        cfg = self._gather_config()
        if cfg is None:
            logging.error("Invalid configuration value — check the Settings tab.")
            self._show_tab("settings")
            return
        save_config(cfg)

        try:
            from jnius import autoclass

            service = autoclass("de.upb.syssec.dpyproxy.ServiceDpyproxyservice")
            mActivity = autoclass("org.kivy.android.PythonActivity").mActivity
            argument = ""
            service.start(mActivity, argument)

        except Exception as e:
            logging.error(f"Service start error: {e}")
            return

        self.start_btn.disabled = True
        self.stop_btn.disabled = False
        self._set_config_locked(True)
        self._set_status("Starting…", AMBER)
        self.log_label.text = "[Starting service...]"
        logging.info("Service started!")

    def stop_service(self, instance):
        with open(STOP_FILE, "w") as f:
            f.write("stop")

        try:
            from jnius import autoclass

            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            Intent = autoclass("android.content.Intent")
            context = PythonActivity.mActivity

            service_class = autoclass("de.upb.syssec.dpyproxy.ServiceDpyproxyservice")
            intent = Intent(context, service_class)
            context.stopService(intent)

        except Exception as e:
            logging.warning(f"Service stop error: {e}")

        # The OS can kill the service process before it finishes writing its
        # own 'stopped' status, leaving a stale 'running' entry that polling
        # would otherwise keep re-applying every second. Drop it and reflect
        # the stop immediately instead.
        if os.path.exists(STATUS_FILE):
            os.remove(STATUS_FILE)
        self._last_ts = 0.0
        self._last_log = ""

        self._reset_buttons()
        self._set_status("Stopped", TEXT_DIM)
        logging.info("Stop signal sent.")

    def _poll_status(self, dt):
        """Read status file written by service and update UI."""
        try:
            if not os.path.exists(STATUS_FILE):
                return
            with open(STATUS_FILE) as f:
                data = json.load(f)

            ts = data.get("ts", 0.0)
            log = data.get("log", "")

            if ts != self._last_ts:
                self._last_ts = ts
                if log != self._last_log:
                    new_text = log[len(self._last_log) :]
                    if new_text.strip():
                        self.log_label.text += new_text
                        self.scroll_view.scroll_y = 0
                    self._last_log = log

            status = data.get("status", "")
            if status == "running":
                self._set_status("Running", GREEN)
            elif status == "starting":
                self._set_status("Starting…", AMBER)
            elif status == "stopping":
                self._set_status("Stopping…", AMBER)
            elif status in ("stopped", "error"):
                self._set_status("Stopped" if status == "stopped" else "Error", RED if status == "error" else TEXT_DIM)
                self._reset_buttons()

        except Exception:
            pass

    def _set_status(self, text, color):
        self.status_label.text = text
        self.status_label.color = color
        self.status_dot.set_color(color)

    def _reset_buttons(self):
        self.start_btn.disabled = False
        self.stop_btn.disabled = True
        self._set_config_locked(False)

    # -- lifecycle -----------------------------------------------------

    def on_pause(self):
        return True

    def on_resume(self):
        # SDL2's GL context on Android can be recreated after the app is
        # backgrounded, leaving previously rendered canvases (card
        # backgrounds, log text) blank. Re-adding the root widget forces
        # Kivy to reissue every canvas instruction against the current
        # context instead of leaving stale/black framebuffers.
        Clock.schedule_once(self._refresh_after_resume, 0)

    def _refresh_after_resume(self, dt):
        root = self.root
        parent = root.parent if root else None
        if parent:
            parent.remove_widget(root)
            parent.add_widget(root)


if __name__ == "__main__":
    DPYProxyApp().run()
