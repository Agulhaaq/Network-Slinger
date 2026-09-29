"""
Single-Instance Application Manager and Native Window Runner.
Guarantees only one instance of Network Slinger runs at a time.
Provides native standalone window launch via pywebview or automated browser focus.
"""

import atexit
import ctypes
import os
import platform
import socket
import sys
import tempfile
import threading
import time
import webbrowser
from typing import Optional

PORT_FILE = os.path.join(tempfile.gettempdir(), "networkslinger_active_port.txt")


class SingleInstanceLock:
    """
    Enforces a single-instance constraint using Windows Named Mutex
    or filesystem lock on Unix.
    """
    def __init__(self, app_id: str = "NetworkSlinger_SingleInstance_App"):
        self.app_id = app_id
        self.mutex_handle = None
        self.lock_file = None
        self.is_locked = False

    def acquire(self) -> bool:
        """Returns True if this is the only running instance, False if another exists."""
        if platform.system() == "Windows":
            ERROR_ALREADY_EXISTS = 183
            try:
                self.mutex_handle = ctypes.windll.kernel32.CreateMutexW(
                    None, True, f"Global\\{self.app_id}"
                )
                last_error = ctypes.windll.kernel32.GetLastError()
                if last_error == ERROR_ALREADY_EXISTS:
                    if self.mutex_handle:
                        ctypes.windll.kernel32.CloseHandle(self.mutex_handle)
                        self.mutex_handle = None
                    self.is_locked = False
                    return False
                self.is_locked = True
                atexit.register(self.release)
                return True
            except Exception:
                pass

        # Fallback lock file mechanism
        lock_path = os.path.join(tempfile.gettempdir(), f"{self.app_id}.lock")
        try:
            if os.path.exists(lock_path):
                with open(lock_path, "r") as f:
                    content = f.read().strip()
                if content.isdigit():
                    pid = int(content)
                    import psutil
                    if psutil.pid_exists(pid):
                        return False
            with open(lock_path, "w") as f:
                f.write(str(os.getpid()))
            self.lock_file = lock_path
            self.is_locked = True
            atexit.register(self.release)
            return True
        except Exception:
            return True

    def release(self):
        """Releases the lock and temporary port registration."""
        if self.mutex_handle and platform.system() == "Windows":
            try:
                ctypes.windll.kernel32.CloseHandle(self.mutex_handle)
                self.mutex_handle = None
            except Exception:
                pass
        if self.lock_file and os.path.exists(self.lock_file):
            try:
                os.remove(self.lock_file)
                self.lock_file = None
            except Exception:
                pass
        if os.path.exists(PORT_FILE):
            try:
                os.remove(PORT_FILE)
            except Exception:
                pass
        self.is_locked = False


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks if the local port is currently occupied by a running server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def focus_existing_window() -> bool:
    """Brings existing native desktop window to the foreground if running."""
    if platform.system() == "Windows":
        try:
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            found_hwnds = []

            def enum_proc(hwnd, lparam):
                if user32.IsWindowVisible(hwnd):
                    length = user32.GetWindowTextLengthW(hwnd)
                    if length > 0:
                        buffer = ctypes.create_unicode_buffer(length + 1)
                        user32.GetWindowTextW(hwnd, buffer, length + 1)
                        if "network slinger" in buffer.value.lower():
                            found_hwnds.append(hwnd)
                            return False
                return True

            WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
            user32.EnumWindows(WNDENUMPROC(enum_proc), 0)

            if found_hwnds:
                hwnd = found_hwnds[0]
                user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                user32.SetForegroundWindow(hwnd)
                # Force window to top of z-order
                HWND_TOP = 0
                SWP_NOMOVE = 0x0002
                SWP_NOSIZE = 0x0001
                SWP_SHOWWINDOW = 0x0040
                user32.SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
                return True
        except Exception:
            pass
    return False


def run_one_time_instance(host: str = "127.0.0.1", port: int = 8000, native_window: bool = True):
    """
    Main entrypoint for single-instance launch.
    - If already running: focuses window or opens active browser instance and exits cleanly.
    - If not running: acquires single-instance lock, launches server, and opens native window or browser.
    """
    lock = SingleInstanceLock()
    target_url = f"http://{host}:{port}"

    # Check if another instance is already holding the lock
    if not lock.acquire():
        # Read the active port if available
        if os.path.exists(PORT_FILE):
            try:
                with open(PORT_FILE, "r") as f:
                    content = f.read().strip()
                if content:
                    target_url = f"http://{content}"
            except Exception:
                pass

        print(f"[INFO] Network Slinger instance is already running.")
        if native_window and focus_existing_window():
            print(f"[INFO] Restored and focused active desktop window.")
        else:
            print(f"[INFO] Opening active instance in browser: {target_url}")
            webbrowser.open(target_url)
        sys.exit(0)

    # If the requested port is occupied by another application, find next free port
    original_port = port
    while is_port_in_use(port, host) and port < original_port + 20:
        port += 1
    target_url = f"http://{host}:{port}"

    # Record active host:port
    try:
        with open(PORT_FILE, "w") as f:
            f.write(f"{host}:{port}")
    except Exception:
        pass

    # Start FastAPI server in a background daemon thread
    from .web.server import app
    import uvicorn

    server_thread = threading.Thread(
        target=lambda: uvicorn.run(app, host=host, port=port, log_level="warning"),
        daemon=True
    )
    server_thread.start()

    # Wait for server to bind
    for _ in range(30):
        if is_port_in_use(port, host):
            break
        time.sleep(0.1)

    print(f"[+] Network Slinger single-instance running at: {target_url}")

    # Launch native desktop window via pywebview if requested and available
    if native_window:
        try:
            import webview
            window = webview.create_window(
                title="Network Slinger - Asset Discovery & Reconnaissance",
                url=target_url,
                width=1280,
                height=840,
                min_size=(960, 640),
                background_color="#000000"
            )
            try:
                webview.start(gui="edgechromium", private_mode=True)
            except Exception:
                webview.start()
            lock.release()
            sys.exit(0)
        except Exception as e:
            # Fallback to default system browser
            print(f"[INFO] Native window unavailable ({e}). Launching in browser.")

    # Fallback to browser
    webbrowser.open(target_url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down Network Slinger instance.")
        lock.release()
