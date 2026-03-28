import hashlib
import hmac
import json
import math
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from pathlib import Path
from tkinter import messagebox, simpledialog


API_BASE = os.getenv("EXE_API_BASE", "http://localhost:5000")
EXE_LOGIN_ENDPOINT = f"{API_BASE.rstrip('/')}/api/exe/login"
EXE_UPDATE_ENDPOINT = f"{API_BASE.rstrip('/')}/api/exe/update"
EXE_TAMPER_ENDPOINT = f"{API_BASE.rstrip('/')}/api/exe/tamper"
LAUNCHER_VERSION = "2.6.0"
EXE_SIGNING_SECRET = os.getenv("EXE_SIGNING_SECRET", "cloudx-exe-signing-v1")
SETTINGS_PATH = Path.home() / ".cloudx_launcher_settings.json"
ENABLE_EXE_ANTITAMPER = os.getenv("ENABLE_EXE_ANTITAMPER", "1").strip().lower() not in ("0", "false", "no")
PLACEHOLDER_SERVER_MARKERS = ("your-public-domain.com", "example.com", "set_me")

SUSPICIOUS_TOOL_NAMES = (
    "x64dbg.exe",
    "x32dbg.exe",
    "ollydbg.exe",
    "ida64.exe",
    "ida.exe",
    "dnspy.exe",
    "dnspy-x86.exe",
    "processhacker.exe",
    "wireshark.exe",
    "fiddler.exe",
    "charles.exe",
)


def _extract_first_useful_line(output: str) -> str:
    for line in output.splitlines():
        normalized = line.strip()
        if not normalized:
            continue
        lower = normalized.lower()
        if any(token in lower for token in ("serialnumber", "processorid", "caption", "name")):
            continue
        return normalized
    return ""


def _run_command(command: str) -> str:
    try:
        completed = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return (completed.stdout or "").strip()
    except Exception:
        return ""


def get_machine_guid() -> str:
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value).strip()
    except Exception:
        return ""


def build_hwid() -> str:
    machine_guid = get_machine_guid()
    bios_serial = _extract_first_useful_line(_run_command("wmic bios get serialnumber"))
    board_serial = _extract_first_useful_line(_run_command("wmic baseboard get serialnumber"))
    cpu_id = _extract_first_useful_line(_run_command("wmic cpu get ProcessorId"))

    raw = "|".join(
        [
            machine_guid,
            bios_serial,
            board_serial,
            cpu_id,
            hex(uuid.getnode()),
            platform.node(),
            platform.system(),
            platform.release(),
            platform.machine(),
        ]
    )

    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest().upper()
    return f"PY-{digest[:32]}"


def get_public_ip() -> str:
    urls = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
        "https://ipv4.icanhazip.com",
    ]
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                data = response.read().decode("utf-8", errors="ignore").strip()
                if not data:
                    continue
                if "format=json" in url:
                    parsed = json.loads(data)
                    ip = str(parsed.get("ip", "")).strip()
                else:
                    ip = data
                if ip:
                    return ip
        except Exception:
            continue
    return ""


def compare_versions(version_a: str, version_b: str) -> int:
    a_parts = [int(part) if part.isdigit() else 0 for part in str(version_a or "").split(".")]
    b_parts = [int(part) if part.isdigit() else 0 for part in str(version_b or "").split(".")]
    max_len = max(len(a_parts), len(b_parts))
    for idx in range(max_len):
        av = a_parts[idx] if idx < len(a_parts) else 0
        bv = b_parts[idx] if idx < len(b_parts) else 0
        if av > bv:
            return 1
        if av < bv:
            return -1
    return 0


def load_settings() -> dict:
    try:
        if not SETTINGS_PATH.exists():
            return {}
        return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_settings(data: dict):
    try:
        SETTINGS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        return


def create_login_signature(username: str, password: str, hwid: str, client_ip: str, ts: int, nonce: str) -> str:
    payload = json.dumps(
        [str(username or ""), str(password or ""), str(hwid or ""), str(client_ip or ""), str(ts), str(nonce)],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hmac.new(EXE_SIGNING_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def create_signed_headers(username: str, password: str, hwid: str, client_ip: str):
    ts = int(time.time())
    nonce = uuid.uuid4().hex
    signature = create_login_signature(username, password, hwid, client_ip, ts, nonce)
    return {
        "Content-Type": "application/json",
        "X-Exe-Ts": str(ts),
        "X-Exe-Nonce": nonce,
        "X-Exe-Signature": signature,
    }


def normalize_api_base(value: str) -> str:
    normalized = str(value or "").replace("\ufeff", "").strip().strip('"').strip("'")
    if not normalized:
        return ""
    if not normalized.startswith("http://") and not normalized.startswith("https://"):
        if normalized.startswith("localhost") or normalized.startswith("127.") or normalized.startswith("::1"):
            normalized = f"http://{normalized}"
        else:
            normalized = f"https://{normalized}"
    try:
        parsed = urllib.parse.urlparse(normalized)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    except Exception:
        pass
    return normalized.rstrip("/")


def has_placeholder_server_url(value: str) -> bool:
    lowered = str(value or "").strip().lower()
    if not lowered:
        return True
    return any(marker in lowered for marker in PLACEHOLDER_SERVER_MARKERS)


def is_capslock_enabled() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.user32.GetKeyState(0x14) & 1)
    except Exception:
        return False


def is_debugger_present() -> bool:
    try:
        import ctypes

        if ctypes.windll.kernel32.IsDebuggerPresent():
            return True
        remote_debugger = ctypes.c_int(0)
        ctypes.windll.kernel32.CheckRemoteDebuggerPresent(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(remote_debugger))
        if remote_debugger.value != 0:
            return True
    except Exception:
        return False
    return False


def detect_suspicious_processes():
    output = _run_command("tasklist")
    if not output:
        return []

    process_names = set()
    for line in output.splitlines():
        raw = line.strip()
        if not raw or raw.lower().startswith("image name"):
            continue
        parts = raw.split()
        if not parts:
            continue
        image_name = parts[0].strip().lower()
        if image_name.endswith(".exe"):
            process_names.add(image_name)

    return sorted(name for name in SUSPICIOUS_TOOL_NAMES if name in process_names)


class LauncherApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Cloud X Streamer Launcher")
        self.root.geometry("820x620")
        self.root.minsize(780, 560)
        self.root.configure(bg="#050913")

        self.is_loading = False
        self.loader_angle = 0
        self.loading_window = None
        self.loading_canvas = None
        self.loading_note = None
        self.loading_progress = None
        self.loading_phase = 0
        self.loading_pct = 0

        self.title_phase = 0
        self.button_phase = 0
        self.button_hovered = False
        self.title_variants = [
            "CLOUD X STREMER",
            "STREMER 404 LIMITED",
        ]
        self.title_variant_index = 0
        self.title_target = self.title_variants[0]
        self.title_glitch_chars = "STREMER404LIMITEDCLOUDX "
        self.subtitle_text = [
            "Secure Python EXE Login",
            "HWID + Public IP Sync",
            "Admin-Controlled Access",
        ]
        self.subtitle_index = 0
        self.subtitle_char = 0
        self.subtitle_deleting = False
        self.status_phase = 0
        self.status_target_color = "#9fb4da"
        self.status_animating = False
        self.update_in_progress = False
        self.update_prompted = False
        self.security_blocked = False

        self.settings = load_settings()
        self.remember_username = tk.BooleanVar(value=bool(self.settings.get("remember_username", True)))
        self.show_password = tk.BooleanVar(value=False)
        sidecar_api_base = ""
        self.sidecar_config_file = None
        try:
            if getattr(sys, "frozen", False):
                self.sidecar_config_file = Path(sys.executable).resolve().with_name("server_url.txt")
                if self.sidecar_config_file.exists():
                    sidecar_api_base = self.sidecar_config_file.read_text(encoding="utf-8-sig").strip()
        except Exception:
            sidecar_api_base = ""

        self.api_base = normalize_api_base(sidecar_api_base or self.settings.get("api_base") or API_BASE) or normalize_api_base(API_BASE)
        self.base_particles = []
        self.theme_palettes = {
            "none": {"accent": "#27d3ff", "accent_alt": "#7ff6ff", "title_a": "#69dcff", "title_b": "#97ffd1", "border": "#2a4f86"},
            "lite": {"accent": "#2cd6ff", "accent_alt": "#8ff7ff", "title_a": "#60d8ff", "title_b": "#8fffd8", "border": "#2a5f96"},
            "pro": {"accent": "#d65cff", "accent_alt": "#f29bff", "title_a": "#d969ff", "title_b": "#ff9bd2", "border": "#7031a6"},
            "max": {"accent": "#ff9b2c", "accent_alt": "#ffd48f", "title_a": "#ffb24d", "title_b": "#ffd890", "border": "#8f5224"},
            "ultra": {"accent": "#4dff87", "accent_alt": "#adffc6", "title_a": "#67ff9a", "title_b": "#bfffd7", "border": "#2f8b57"},
        }
        self.current_theme = "none"
        self.accent_primary = self.theme_palettes["none"]["accent"]
        self.accent_secondary = self.theme_palettes["none"]["accent_alt"]
        self.title_color_a = self.theme_palettes["none"]["title_a"]
        self.title_color_b = self.theme_palettes["none"]["title_b"]

        startup_tamper_reason = self._run_startup_security_checks()
        if startup_tamper_reason:
            self._trigger_tamper_block(startup_tamper_reason, immediate=True)
            return

        self._build_ui()
        self._prompt_server_url_if_needed()
        self._start_intro()
        self._animate_background()
        self._animate_title()
        self._start_title_swap_loop()
        self._animate_subtitle()
        self._animate_button()
        self._monitor_capslock()
        self._start_update_check()
        self._start_runtime_guard()

    @staticmethod
    def _hex_to_rgb(value: str):
        value = value.strip("#")
        return tuple(int(value[i : i + 2], 16) for i in (0, 2, 4))

    @staticmethod
    def _rgb_to_hex(rgb):
        return "#{:02x}{:02x}{:02x}".format(
            max(0, min(255, int(rgb[0]))),
            max(0, min(255, int(rgb[1]))),
            max(0, min(255, int(rgb[2]))),
        )

    def _interpolate_color(self, color_a: str, color_b: str, t: float) -> str:
        a = self._hex_to_rgb(color_a)
        b = self._hex_to_rgb(color_b)
        mixed = (
            a[0] + (b[0] - a[0]) * t,
            a[1] + (b[1] - a[1]) * t,
            a[2] + (b[2] - a[2]) * t,
        )
        return self._rgb_to_hex(mixed)

    def _build_ui(self):
        self.bg_canvas = tk.Canvas(self.root, bg="#050913", highlightthickness=0)
        self.bg_canvas.pack(fill="both", expand=True)
        self.bg_canvas.bind("<Configure>", self._on_resize)

        self.shadow = tk.Frame(self.root, bg="#03060f")
        self.card = tk.Frame(self.root, bg="#0c142a", highlightthickness=1, highlightbackground="#2a4f86")

        self.shadow_window = self.bg_canvas.create_window(0, 0, window=self.shadow, anchor="nw")
        self.card_window = self.bg_canvas.create_window(0, 0, window=self.card, anchor="nw")

        self.badge = tk.Label(
            self.card,
            text="CLOUD X // SECURE NODE",
            fg="#85bbff",
            bg="#0c142a",
            font=("Consolas", 10, "bold"),
        )
        self.badge.pack(anchor="w", padx=32, pady=(26, 8))

        self.title_label = tk.Label(
            self.card,
            text=self.title_target,
            fg="#7cefff",
            bg="#0c142a",
            font=("Segoe UI Black", 30, "bold"),
        )
        self.title_label.pack(anchor="w", padx=32)

        self.subtitle_label = tk.Label(
            self.card,
            text="",
            fg="#9fb4da",
            bg="#0c142a",
            font=("Segoe UI", 12),
        )
        self.subtitle_label.pack(anchor="w", padx=34, pady=(8, 18))

        self.separator = tk.Frame(self.card, bg="#1d2f55", height=1)
        self.separator.pack(fill="x", padx=32, pady=(0, 18))

        form = tk.Frame(self.card, bg="#0c142a")
        form.pack(fill="x", padx=32)

        tk.Label(form, text="USERNAME", fg="#79aef5", bg="#0c142a", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.username_entry = tk.Entry(
            form,
            bg="#081024",
            fg="#eff5ff",
            insertbackground="#eff5ff",
            relief="flat",
            highlightthickness=2,
            highlightbackground="#1a2d50",
            highlightcolor="#2ce4ff",
            font=("Segoe UI", 13),
        )
        self.username_entry.pack(fill="x", ipady=11, pady=(7, 14))
        self.username_entry.bind("<FocusIn>", lambda _event: self._set_entry_focus(self.username_entry, True))
        self.username_entry.bind("<FocusOut>", lambda _event: self._set_entry_focus(self.username_entry, False))
        self.username_entry.bind("<Return>", lambda _event: self._focus_password())
        self.username_entry.bind("<Tab>", lambda _event: self._focus_password())

        saved_username = str(self.settings.get("username", "")).strip()
        if self.remember_username.get() and saved_username:
            self.username_entry.insert(0, saved_username)

        tk.Label(form, text="PASSWORD", fg="#79aef5", bg="#0c142a", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.password_entry = tk.Entry(
            form,
            show="*",
            bg="#081024",
            fg="#eff5ff",
            insertbackground="#eff5ff",
            relief="flat",
            highlightthickness=2,
            highlightbackground="#1a2d50",
            highlightcolor="#2ce4ff",
            font=("Segoe UI", 13),
        )
        self.password_entry.pack(fill="x", ipady=11, pady=(7, 16))
        self.password_entry.bind("<Return>", lambda _event: self.on_login())
        self.password_entry.bind("<Tab>", lambda _event: self._focus_login_button())
        self.password_entry.bind("<KeyRelease>", lambda _event: self._update_caps_warning())
        self.password_entry.bind("<FocusIn>", lambda _event: self._set_entry_focus(self.password_entry, True))
        self.password_entry.bind("<FocusOut>", lambda _event: self._set_entry_focus(self.password_entry, False))

        options = tk.Frame(form, bg="#0c142a")
        options.pack(fill="x", pady=(0, 8))
        self.remember_check = tk.Checkbutton(
            options,
            text="Remember username",
            variable=self.remember_username,
            command=self._on_remember_toggle,
            bg="#0c142a",
            fg="#88a9d6",
            activebackground="#0c142a",
            activeforeground="#a5c7ff",
            selectcolor="#0c142a",
            font=("Segoe UI", 9),
            bd=0,
            highlightthickness=0,
        )
        self.remember_check.pack(side="left")
        self.show_password_check = tk.Checkbutton(
            options,
            text="Show password",
            variable=self.show_password,
            command=self._toggle_show_password,
            bg="#0c142a",
            fg="#88a9d6",
            activebackground="#0c142a",
            activeforeground="#a5c7ff",
            selectcolor="#0c142a",
            font=("Segoe UI", 9),
            bd=0,
            highlightthickness=0,
        )
        self.show_password_check.pack(side="right")

        self.caps_label = tk.Label(
            form,
            text="Caps Lock is ON",
            fg="#ff9a7a",
            bg="#0c142a",
            font=("Segoe UI", 9, "bold"),
        )
        self.caps_label.pack(anchor="w", pady=(0, 6))
        self.caps_label.pack_forget()

        self.status_label = tk.Label(
            form,
            text="Enter credentials to deploy secure session.",
            fg="#9fb4da",
            bg="#0c142a",
            font=("Segoe UI", 10),
        )
        self.status_label.pack(anchor="w", pady=(2, 12))

        self.login_btn = tk.Button(
            form,
            text="LOGIN",
            bg="#27d3ff",
            fg="#02101a",
            activebackground="#74ebff",
            activeforeground="#02101a",
            font=("Segoe UI", 13, "bold"),
            relief="flat",
            cursor="hand2",
            command=self.on_login,
        )
        self.login_btn.pack(fill="x", ipady=11)
        self.login_btn.bind("<Enter>", self._button_enter)
        self.login_btn.bind("<Leave>", self._button_leave)
        self.login_btn.bind("<ButtonPress-1>", self._button_press)
        self.login_btn.bind("<ButtonRelease-1>", self._button_release)

        self.footer = tk.Label(
            self.card,
            text="Your device fingerprint and public IP are auto-synced after successful login.",
            fg="#6480ac",
            bg="#0c142a",
            font=("Segoe UI", 9),
        )
        self.footer.pack(anchor="w", padx=34, pady=(10, 14))

    def _on_resize(self, _event=None):
        width = self.bg_canvas.winfo_width()
        height = self.bg_canvas.winfo_height()
        if width <= 2 or height <= 2:
            return

        self.bg_canvas.delete("gradient")
        for y in range(height):
            t = y / max(1, height - 1)
            color = self._interpolate_color("#070b18", "#0b1630", t)
            self.bg_canvas.create_line(0, y, width, y, fill=color, tags=("gradient",))

        card_w = min(740, max(650, width - 70))
        card_h = min(560, max(490, height - 60))
        x = (width - card_w) // 2
        y = (height - card_h) // 2

        self.bg_canvas.itemconfigure(self.shadow_window, width=card_w, height=card_h)
        self.bg_canvas.coords(self.shadow_window, x + 8, y + 10)
        self.bg_canvas.itemconfigure(self.card_window, width=card_w, height=card_h)
        self.bg_canvas.coords(self.card_window, x, y)

        self._ensure_particles(width, height)

    def _ensure_particles(self, width: int, height: int):
        if self.base_particles:
            return
        palette = ["#1d8dff", "#27d3ff", "#34f0c2", "#9b7cff"]
        for _ in range(18):
            radius = random.randint(18, 42)
            particle = {
                "x": random.uniform(0, width),
                "y": random.uniform(0, height),
                "r": radius,
                "vx": random.uniform(-0.35, 0.35),
                "vy": random.uniform(-0.35, 0.35),
                "color": random.choice(palette),
                "id": None,
                "glow": None,
            }
            glow_color = self._interpolate_color(particle["color"], "#0b1630", 0.75)
            particle["glow"] = self.bg_canvas.create_oval(0, 0, 0, 0, fill=glow_color, outline="", tags=("particle",))
            particle["id"] = self.bg_canvas.create_oval(0, 0, 0, 0, fill=particle["color"], outline="", tags=("particle",))
            self.base_particles.append(particle)
        self.bg_canvas.tag_lower("particle")

    def _animate_background(self):
        width = max(1, self.bg_canvas.winfo_width())
        height = max(1, self.bg_canvas.winfo_height())
        if self.base_particles:
            for particle in self.base_particles:
                particle["x"] += particle["vx"]
                particle["y"] += particle["vy"]
                if particle["x"] < -particle["r"]:
                    particle["x"] = width + particle["r"]
                elif particle["x"] > width + particle["r"]:
                    particle["x"] = -particle["r"]
                if particle["y"] < -particle["r"]:
                    particle["y"] = height + particle["r"]
                elif particle["y"] > height + particle["r"]:
                    particle["y"] = -particle["r"]

                r = particle["r"]
                x = particle["x"]
                y = particle["y"]
                self.bg_canvas.coords(particle["glow"], x - r * 1.8, y - r * 1.8, x + r * 1.8, y + r * 1.8)
                self.bg_canvas.coords(particle["id"], x - r * 0.35, y - r * 0.35, x + r * 0.35, y + r * 0.35)

        self.root.after(42, self._animate_background)

    def _start_intro(self):
        try:
            self.root.attributes("-alpha", 0.0)
            self._fade_in(0.0)
        except Exception:
            return

    def _fade_in(self, alpha: float):
        try:
            if alpha >= 1.0:
                self.root.attributes("-alpha", 1.0)
                return
            self.root.attributes("-alpha", alpha)
            self.root.after(20, lambda: self._fade_in(alpha + 0.07))
        except Exception:
            return

    def _animate_title(self):
        if not self.title_label.winfo_exists():
            return
        pulse = (1 + math.sin(self.title_phase / 8.0)) / 2
        color = self._interpolate_color(self.title_color_a, self.title_color_b, pulse)
        self.title_label.config(fg=color)
        self.title_phase = (self.title_phase + 1) % 100000
        self.root.after(55, self._animate_title)

    def _start_title_swap_loop(self):
        self.root.after(2000, self._switch_title_text)

    def _switch_title_text(self):
        if not self.title_label.winfo_exists():
            return
        next_index = (self.title_variant_index + 1) % len(self.title_variants)
        target = self.title_variants[next_index]
        self._animate_title_glitch(target, 0)

    def _animate_title_glitch(self, target: str, frame: int):
        if not self.title_label.winfo_exists():
            return

        if frame < 8:
            scrambled = "".join(random.choice(self.title_glitch_chars) for _ in range(len(target)))
            self.title_label.config(text=scrambled)
            self.root.after(65, lambda: self._animate_title_glitch(target, frame + 1))
            return

        self.title_variant_index = (self.title_variant_index + 1) % len(self.title_variants)
        self.title_target = target
        self.title_label.config(text=self.title_target)
        self.root.after(2000, self._switch_title_text)

    def _animate_subtitle(self):
        if not self.subtitle_label.winfo_exists():
            return

        full = self.subtitle_text[self.subtitle_index]
        if not self.subtitle_deleting:
            self.subtitle_char = min(len(full), self.subtitle_char + 1)
            shown = full[: self.subtitle_char]
            self.subtitle_label.config(text=f"{shown}_")
            if self.subtitle_char >= len(full):
                self.subtitle_deleting = True
                self.root.after(900, self._animate_subtitle)
                return
            delay = 46
        else:
            self.subtitle_char = max(0, self.subtitle_char - 1)
            shown = full[: self.subtitle_char]
            self.subtitle_label.config(text=f"{shown}_")
            if self.subtitle_char == 0:
                self.subtitle_deleting = False
                self.subtitle_index = (self.subtitle_index + 1) % len(self.subtitle_text)
                self.root.after(200, self._animate_subtitle)
                return
            delay = 28

        self.root.after(delay, self._animate_subtitle)

    def _animate_button(self):
        if not self.login_btn.winfo_exists():
            return
        if self.login_btn["state"] == "disabled":
            self.root.after(120, self._animate_button)
            return
        if not self.button_hovered:
            t = (1 + math.sin(self.button_phase / 6.5)) / 2
            bg = self._interpolate_color(self.accent_primary, self.accent_secondary, t)
            self.login_btn.config(bg=bg, activebackground=self.accent_secondary)
        self.button_phase = (self.button_phase + 1) % 100000
        self.root.after(65, self._animate_button)

    def _set_entry_focus(self, entry: tk.Entry, focused: bool):
        if focused:
            entry.config(highlightbackground=self.accent_primary, highlightcolor=self.accent_primary)
        else:
            entry.config(highlightbackground="#1a2d50", highlightcolor="#1a2d50")
        self._update_caps_warning()

    def _focus_password(self):
        self.password_entry.focus_set()
        self.password_entry.icursor(tk.END)
        return "break"

    def _focus_login_button(self):
        self.login_btn.focus_set()
        return "break"

    def _toggle_show_password(self):
        self.password_entry.config(show="" if self.show_password.get() else "*")

    def _on_remember_toggle(self):
        self.settings["remember_username"] = bool(self.remember_username.get())
        if not self.remember_username.get():
            self.settings["username"] = ""
        save_settings(self.settings)

    def _update_caps_warning(self):
        show_warning = self.password_entry.focus_get() == self.password_entry and is_capslock_enabled()
        if show_warning and not self.caps_label.winfo_manager():
            self.caps_label.pack(anchor="w", pady=(0, 6), before=self.status_label)
        if not show_warning and self.caps_label.winfo_manager():
            self.caps_label.pack_forget()

    def _monitor_capslock(self):
        self._update_caps_warning()
        self.root.after(350, self._monitor_capslock)

    def _apply_theme(self, theme_name: str):
        normalized = theme_name if theme_name in self.theme_palettes else "none"
        palette = self.theme_palettes[normalized]
        self.current_theme = normalized
        self.accent_primary = palette["accent"]
        self.accent_secondary = palette["accent_alt"]
        self.title_color_a = palette["title_a"]
        self.title_color_b = palette["title_b"]

        self.card.config(highlightbackground=palette["border"])
        self.badge.config(fg=palette["accent_alt"])
        if self.login_btn["state"] != "disabled":
            self.login_btn.config(bg=palette["accent"], activebackground=palette["accent_alt"])

    def _prompt_server_url_if_needed(self):
        if not getattr(sys, "frozen", False):
            return
        if not has_placeholder_server_url(self.api_base):
            return

        self.set_status("Server URL not configured. Please enter your real backend URL.", "#ffb27a")
        entered = simpledialog.askstring(
            "Server URL Required",
            "Enter your backend URL (example: https://api.yourdomain.com):",
            initialvalue="https://",
            parent=self.root,
        )
        if not entered:
            self.set_status("Server URL missing. Login will fail until configured.", "#ff8c8c")
            return

        normalized = normalize_api_base(entered)
        if not normalized or has_placeholder_server_url(normalized):
            self.set_status("Invalid server URL. Set a real domain URL.", "#ff8c8c")
            return

        self.api_base = normalized
        self.settings["api_base"] = normalized
        save_settings(self.settings)
        try:
            if self.sidecar_config_file:
                self.sidecar_config_file.write_text(normalized, encoding="utf-8")
        except Exception:
            pass
        self.set_status(f"Server set: {normalized}", "#6bffb3")

    def _run_startup_security_checks(self) -> str:
        if not ENABLE_EXE_ANTITAMPER:
            return ""
        if not getattr(sys, "frozen", False):
            return ""
        if sys.gettrace() is not None:
            return "Debugger trace hook detected at startup."
        if is_debugger_present():
            return "Native debugger detected at startup."
        suspicious = detect_suspicious_processes()
        if suspicious:
            return f"Suspicious analysis tools detected: {', '.join(suspicious)}"
        return ""

    def _start_runtime_guard(self):
        if not ENABLE_EXE_ANTITAMPER or not getattr(sys, "frozen", False):
            return
        self.root.after(3500, self._runtime_guard_tick)

    def _runtime_guard_tick(self):
        if self.security_blocked:
            return
        reason = ""
        if sys.gettrace() is not None:
            reason = "Runtime debugger trace hook detected."
        elif is_debugger_present():
            reason = "Runtime debugger detected."
        else:
            suspicious = detect_suspicious_processes()
            if suspicious:
                reason = f"Runtime analysis tools detected: {', '.join(suspicious)}"

        if reason:
            self._trigger_tamper_block(reason, immediate=False)
            return

        self.root.after(3500, self._runtime_guard_tick)

    def _trigger_tamper_block(self, reason: str, immediate: bool):
        if self.security_blocked:
            return
        self.security_blocked = True

        username = ""
        if hasattr(self, "username_entry"):
            try:
                username = self.username_entry.get().strip()
            except Exception:
                username = ""

        threading.Thread(target=self._send_tamper_report_worker, args=(username, reason), daemon=True).start()

        if hasattr(self, "login_btn"):
            try:
                self.login_btn.config(state="disabled", text="BLOCKED")
            except Exception:
                pass
        if hasattr(self, "status_label"):
            self.set_status("Security violation detected. Access blocked.", "#ff8c8c")

        def _notify_and_close():
            messagebox.showerror("Security Blocked", "Security violation detected. This launcher instance is blocked.")
            self.root.destroy()

        delay = 100 if immediate else 650
        self.root.after(delay, _notify_and_close)

    def _send_tamper_report_worker(self, username: str, reason: str):
        try:
            hwid = build_hwid()
            public_ip = get_public_ip()
            payload = {
                "username": username or "unknown",
                "hwid": hwid,
                "reason": "tamper_detected",
                "details": reason,
                "launcher_version": LAUNCHER_VERSION,
            }
            if public_ip:
                payload["clientIp"] = public_ip

            headers = create_signed_headers(payload["username"], "", hwid, public_ip)
            request = urllib.request.Request(
                f"{self.api_base}/api/exe/tamper",
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10):
                pass
        except Exception:
            return

    def _start_update_check(self):
        threading.Thread(target=self._check_update_worker, daemon=True).start()

    def _check_update_worker(self):
        try:
            query = urllib.parse.urlencode({"current_version": LAUNCHER_VERSION})
            url = f"{self.api_base}/api/exe/update?{query}"
            request = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read().decode("utf-8", errors="ignore")
                data = json.loads(body) if body else {}

            latest = str(data.get("latest_version", "")).strip()
            update_url = str(data.get("download_url", "")).strip()
            update_available = bool(data.get("update_available")) or (
                latest and compare_versions(LAUNCHER_VERSION, latest) < 0
            )
            required = bool(data.get("required"))
            notes = str(data.get("notes", "")).strip()

            if not update_available or not latest or not update_url:
                return
            if self.update_prompted:
                return

            self.update_prompted = True
            self.root.after(0, lambda: self._prompt_update(latest, update_url, required, notes))
        except Exception:
            return

    def _prompt_update(self, latest: str, update_url: str, required: bool, notes: str):
        if self.update_in_progress:
            return

        note_text = f"\n\nNotes: {notes}" if notes else ""
        prompt = (
            f"New launcher version {latest} is available (current: {LAUNCHER_VERSION}).{note_text}\n\n"
            f"{'This update is required to continue.' if required else 'Do you want to update now?'}"
        )

        if required:
            proceed = messagebox.askyesno("Required Update", prompt)
            if not proceed:
                self.set_status("Update required. Please restart launcher and update.", "#ff9a7a")
                return
        else:
            proceed = messagebox.askyesno("Launcher Update", prompt)
            if not proceed:
                self.set_status("Skipped update. You can still login.", "#9fb4da")
                return

        self.update_in_progress = True
        self.login_btn.config(state="disabled", text="UPDATING...", bg=self._interpolate_color(self.accent_primary, "#0a1328", 0.35))
        self.set_status("Downloading launcher update...", "#7ed4ff")
        threading.Thread(target=self._download_update_worker, args=(latest, update_url), daemon=True).start()

    def _download_update_worker(self, latest: str, update_url: str):
        temp_dir = None
        try:
            temp_dir = Path(tempfile.mkdtemp(prefix="cloudx_update_"))
            download_target = temp_dir / f"CloudXLauncher_{latest}.exe"

            request = urllib.request.Request(update_url, method="GET")
            with urllib.request.urlopen(request, timeout=30) as response, download_target.open("wb") as out_file:
                total_size = int(response.headers.get("Content-Length", "0") or "0")
                downloaded = 0
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    out_file.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        pct = int((downloaded / total_size) * 100)
                        self.root.after(0, lambda p=pct: self.set_status(f"Downloading update... {p}%", "#7ed4ff"))

            if not getattr(sys, "frozen", False):
                local_copy = Path.cwd() / f"CloudXLauncher_UPDATED_{latest}.exe"
                shutil.copy2(download_target, local_copy)
                self.root.after(
                    0,
                    lambda: self._finish_update_non_frozen(
                        f"Update downloaded to:\n{local_copy}\n\nRun that EXE to use the latest version."
                    ),
                )
                return

            self._schedule_self_update(download_target)
        except Exception as error:
            self.root.after(0, lambda: self._update_failed(str(error) or "Failed to update launcher."))
            if temp_dir:
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception:
                    pass

    def _finish_update_non_frozen(self, message: str):
        self.update_in_progress = False
        self.login_btn.config(state="normal", text="LOGIN", bg=self.accent_primary, activebackground=self.accent_secondary)
        self.set_status("Update downloaded successfully.", "#6bffb3")
        messagebox.showinfo("Launcher Update", message)

    def _schedule_self_update(self, downloaded_exe: Path):
        try:
            current_exe = Path(sys.executable).resolve()
            pid = os.getpid()
            updater_script = Path(tempfile.gettempdir()) / f"cloudx_launcher_updater_{int(time.time())}.bat"
            script = (
                "@echo off\n"
                f"set \"SRC={downloaded_exe}\"\n"
                f"set \"DST={current_exe}\"\n"
                f"set \"PID={pid}\"\n"
                ":waitloop\n"
                "tasklist /FI \"PID eq %PID%\" | find \"%PID%\" >nul\n"
                "if not errorlevel 1 (\n"
                "  timeout /t 1 /nobreak >nul\n"
                "  goto waitloop\n"
                ")\n"
                "copy /y \"%SRC%\" \"%DST%\" >nul\n"
                "start \"\" \"%DST%\"\n"
                "del \"%SRC%\" >nul 2>&1\n"
                "del \"%~f0\" >nul 2>&1\n"
            )
            updater_script.write_text(script, encoding="utf-8")

            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.Popen(["cmd", "/c", str(updater_script)], creationflags=creation_flags)
            self.root.after(0, lambda: self._finish_update_and_exit("Update installed. Restarting launcher..."))
        except Exception as error:
            self.root.after(0, lambda: self._update_failed(str(error) or "Failed to apply update."))

    def _finish_update_and_exit(self, message: str):
        self.set_status(message, "#6bffb3")
        self.root.after(700, self.root.destroy)

    def _update_failed(self, message: str):
        self.update_in_progress = False
        self.login_btn.config(state="normal", text="LOGIN", bg=self.accent_primary, activebackground=self.accent_secondary)
        self.set_status(message, "#ff9a7a")

    def _button_enter(self, _event):
        self.button_hovered = True
        if self.login_btn["state"] != "disabled":
            self.login_btn.config(bg=self.accent_secondary, activebackground=self.accent_secondary, text="LOGIN")

    def _button_leave(self, _event):
        self.button_hovered = False
        if self.login_btn["state"] != "disabled":
            self.login_btn.config(text="LOGIN")

    def _button_press(self, _event):
        if self.login_btn["state"] != "disabled":
            pressed = self._interpolate_color(self.accent_primary, "#0a1328", 0.35)
            self.login_btn.config(bg=pressed, activebackground=pressed)

    def _button_release(self, _event):
        if self.login_btn["state"] != "disabled":
            self.login_btn.config(bg=self.accent_secondary if self.button_hovered else self.accent_primary)

    def set_status(self, text: str, color: str = "#9fb4da"):
        self.status_label.config(text=text)
        self.status_target_color = color
        if not self.status_animating:
            self.status_animating = True
            self.status_phase = 0
            self._animate_status_color()

    def _animate_status_color(self):
        if not self.status_label.winfo_exists():
            self.status_animating = False
            return
        pulse = (1 + math.sin(self.status_phase / 3.5)) / 2
        color = self._interpolate_color("#9fb4da", self.status_target_color, pulse)
        self.status_label.config(fg=color)
        self.status_phase += 1
        if self.status_phase > 10:
            self.status_label.config(fg=self.status_target_color)
            self.status_animating = False
            return
        self.root.after(45, self._animate_status_color)

    def on_login(self):
        if self.is_loading:
            return
        if self.security_blocked:
            return
        if self.update_in_progress:
            self.set_status("Updater is running. Please wait...", "#ffd57a")
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            self.set_status("Username and password are required.", "#ff8c8c")
            return

        if self.remember_username.get():
            self.settings["remember_username"] = True
            self.settings["username"] = username
            save_settings(self.settings)

        self.login_btn.config(state="disabled", text="AUTHENTICATING...", bg=self._interpolate_color(self.accent_primary, "#0a1328", 0.35))
        self.set_status("Verifying credentials and securing session...", "#74c7ff")
        threading.Thread(target=self._login_worker, args=(username, password), daemon=True).start()

    def _login_worker(self, username: str, password: str):
        try:
            hwid = build_hwid()
            public_ip = get_public_ip()
            payload = {
                "username": username,
                "password": password,
                "hwid": hwid,
            }
            if public_ip:
                payload["clientIp"] = public_ip

            headers = create_signed_headers(username, password, hwid, public_ip)

            request = urllib.request.Request(
                f"{self.api_base}/api/exe/login",
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )

            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read().decode("utf-8", errors="ignore")
                data = json.loads(body) if body else {}

            launch_url = data.get("launch_url") or f"{self.api_base}/dashboard.html"
            active_tier = str(data.get("active_tier", "none")).lower().strip()
            tiers = data.get("tiers", {}) if isinstance(data.get("tiers"), dict) else {}
            self.root.after(0, lambda: self._login_success(launch_url, active_tier, tiers))
        except urllib.error.HTTPError as http_error:
            try:
                response_body = http_error.read().decode("utf-8", errors="ignore")
                parsed = json.loads(response_body) if response_body else {}
                message = parsed.get("error", f"Login failed ({http_error.code})")
            except Exception:
                message = f"Login failed ({http_error.code})"
            self.root.after(0, lambda: self._login_error(message))
        except urllib.error.URLError as url_error:
            host_hint = self.api_base
            reason = str(getattr(url_error, "reason", "") or "").strip()
            reason_hint = f" ({reason})" if reason else ""
            if has_placeholder_server_url(host_hint):
                message = (
                    "Server URL is not configured. Set real backend URL in server_url.txt "
                    "next to the EXE."
                )
            else:
                message = (
                    f"Cannot reach auth server: {host_hint}{reason_hint}. "
                    "Check internet, Railway API health URL, and server_url.txt."
                )
            self.root.after(0, lambda: self._login_error(message))
        except Exception as error:
            self.root.after(0, lambda: self._login_error(str(error) or "Unexpected error"))

    def _login_error(self, message: str):
        self.login_btn.config(state="normal", text="LOGIN", bg=self.accent_primary, activebackground=self.accent_secondary)
        self.set_status(message, "#ff8c8c")

    def _login_success(self, launch_url: str, active_tier: str, tiers: dict):
        if not any(bool(tiers.get(key)) for key in ("streamer_lite", "streamer_pro", "streamer_max", "streamer_ultra")):
            active_tier = "none"
        self._apply_theme(active_tier)
        display_tier = active_tier.upper() if active_tier != "none" else "NO PLAN"
        self.set_status(f"Login accepted. Access tier: {display_tier}. Launching...", "#6bffb3")
        self._show_loading()
        threading.Thread(target=self._launch_after_delay, args=(launch_url,), daemon=True).start()

    def _launch_after_delay(self, launch_url: str):
        checkpoints = [
            (10, "Authenticating runtime"),
            (28, "Validating entitlements"),
            (48, "Securing encrypted tunnel"),
            (70, "Preparing app modules"),
            (88, "Finalizing launch sequence"),
        ]
        for pct, note in checkpoints:
            self.root.after(0, lambda p=pct, n=note: self._set_loading_state(p, n))
            time.sleep(0.4)

        for pct in range(89, 101, 2):
            self.root.after(0, lambda p=pct: self._set_loading_state(p, "Launching STREMER 404"))
            time.sleep(0.06)

        try:
            webbrowser.open(launch_url)
        finally:
            self.root.after(0, self._close_loading_and_finish)

    def _show_loading(self):
        self.is_loading = True
        self.loading_window = tk.Toplevel(self.root)
        self.loading_window.title("Cloud X Boot")
        self.loading_window.geometry("520x340")
        self.loading_window.configure(bg="#050a16")
        self.loading_window.resizable(False, False)
        self.loading_window.transient(self.root)
        self.loading_window.grab_set()

        frame = tk.Frame(self.loading_window, bg="#050a16")
        frame.pack(fill="both", expand=True, padx=18, pady=18)

        tk.Label(
            frame,
            text="INITIALIZING STREMER 404",
            fg="#7de9ff",
            bg="#050a16",
            font=("Consolas", 13, "bold"),
        ).pack(anchor="w", pady=(2, 10))

        tk.Label(
            frame,
            text=f"Launcher v{LAUNCHER_VERSION}",
            fg="#5e81b6",
            bg="#050a16",
            font=("Consolas", 9),
        ).pack(anchor="w", pady=(0, 8))

        self.loading_canvas = tk.Canvas(
            frame,
            width=470,
            height=160,
            bg="#091026",
            bd=0,
            highlightthickness=1,
            highlightbackground="#1d3d74",
        )
        self.loading_canvas.pack(fill="x")

        self.loading_note = tk.Label(
            frame,
            text="Preparing secure tunnel",
            fg="#90a7cf",
            bg="#050a16",
            font=("Segoe UI", 10),
        )
        self.loading_note.pack(anchor="w", pady=(10, 6))

        self.loading_progress = tk.Canvas(
            frame,
            width=470,
            height=20,
            bg="#091026",
            bd=0,
            highlightthickness=1,
            highlightbackground="#1d3d74",
        )
        self.loading_progress.pack(fill="x")
        self.loading_phase = 0
        self.loading_pct = 0

        self._animate_loader()

    def _set_loading_state(self, pct: int, note: str):
        self.loading_pct = max(0, min(100, int(pct)))
        if self.loading_note:
            self.loading_note.config(text=note)

    def _animate_loader(self):
        if not self.is_loading or not self.loading_canvas or not self.loading_progress:
            return

        self.loading_canvas.delete("all")
        self.loading_canvas.create_text(
            20,
            22,
            text="AUTH HANDSHAKE",
            fill="#76d8ff",
            font=("Consolas", 10, "bold"),
            anchor="w",
        )

        center_x = 235
        center_y = 86
        self.loading_canvas.create_oval(center_x - 52, center_y - 52, center_x + 52, center_y + 52, outline="#203b69", width=7)
        self.loading_canvas.create_arc(
            center_x - 52,
            center_y - 52,
            center_x + 52,
            center_y + 52,
            start=self.loader_angle,
            extent=120,
            style="arc",
            outline="#39e6ff",
            width=7,
        )
        self.loading_canvas.create_arc(
            center_x - 34,
            center_y - 34,
            center_x + 34,
            center_y + 34,
            start=-self.loader_angle * 1.2,
            extent=95,
            style="arc",
            outline="#75ffbe",
            width=5,
        )

        wave_y = 126 + math.sin(math.radians(self.loader_angle * 3)) * 2
        for i in range(16):
            x1 = 28 + i * 28
            x2 = x1 + 20
            amp = math.sin(math.radians(self.loader_angle * 3 + i * 18))
            y = wave_y + amp * 9
            self.loading_canvas.create_line(x1, y, x2, y, fill="#1fbde6", width=2)

        pulse_x = (self.loader_angle * 2) % 500 - 80
        self.loading_canvas.create_rectangle(pulse_x, 146, pulse_x + 90, 156, fill="#35f0ff", outline="")
        self.loading_canvas.create_text(
            450,
            22,
            text=f"{self.loading_pct:>3d}%",
            fill="#97dbff",
            font=("Consolas", 10, "bold"),
            anchor="e",
        )

        self.loading_progress.delete("all")
        self.loading_progress.create_rectangle(0, 0, 470, 20, fill="#0a142e", outline="")
        fill_width = int((self.loading_pct / 100.0) * 468)
        self.loading_progress.create_rectangle(1, 1, max(1, fill_width), 19, fill="#2cdfff", outline="")
        shimmer = int((self.loader_angle * 4) % 520) - 90
        self.loading_progress.create_rectangle(shimmer, 1, shimmer + 90, 19, fill="#7cf6ff", outline="")

        self.loader_angle = (self.loader_angle + 10) % 360
        self.loading_phase = (self.loading_phase + 1) % 100000
        self.root.after(35, self._animate_loader)

    def _close_loading_and_finish(self):
        self.is_loading = False
        if self.loading_window and self.loading_window.winfo_exists():
            self.loading_window.destroy()
        messagebox.showinfo("Cloud X Launcher", "Main app started.")
        self.root.destroy()


def main():
    root = tk.Tk()
    LauncherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
