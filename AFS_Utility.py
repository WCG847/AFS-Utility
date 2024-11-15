import ctypes
import datetime
import json
import logging
import os
import psutil
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback


import win32con
import win32process
import winreg
import zlib

from functools import partial
from decimal import Decimal
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter import Label
from tkinter import font as tkfont

# Configure logging
log_dir = os.path.join(os.getenv("LOCALAPPDATA"), "WCG847", "AFS Utility", "logs")
try:
    os.makedirs(log_dir, exist_ok=True)
except Exception as e:
    logging.error(f"Error creating log directory: {e}")
    exit(1)

log_file = os.path.join(log_dir, "log.txt")
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logging.info("Application started.")

# Define Windows priority classes
PRIORITY_CLASSES = {
    "IDLE": win32process.IDLE_PRIORITY_CLASS,
    "BELOW_NORMAL": win32process.BELOW_NORMAL_PRIORITY_CLASS,
    "NORMAL": win32process.NORMAL_PRIORITY_CLASS,
    "ABOVE_NORMAL": win32process.ABOVE_NORMAL_PRIORITY_CLASS,
    "HIGH": win32process.HIGH_PRIORITY_CLASS,
    "REALTIME": win32process.REALTIME_PRIORITY_CLASS,
}


def set_process_priority(priority_class):
    """Set the current process's priority."""
    try:
        p = psutil.Process()
        handle = ctypes.windll.kernel32.OpenProcess(
            win32con.PROCESS_ALL_ACCESS, False, p.pid
        )
        win32process.SetPriorityClass(handle, PRIORITY_CLASSES[priority_class])
        ctypes.windll.kernel32.CloseHandle(handle)
        logging.info(f"Process priority set to {priority_class}")
    except Exception as e:
        logging.error(f"Failed to set process priority: {e}")


# Constants for minidump creation
MiniDumpNormal = 0x00000000
MiniDumpWithDataSegs = 0x00000001
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpFilterMemory = 0x00000008
MiniDumpWithUnloadedModules = 0x00000010
MiniDumpWithIndirectlyReferencedMemory = 0x00000020
MiniDumpFilterModulePaths = 0x00000040
MiniDumpWithProcessThreadData = 0x00000080
MiniDumpWithPrivateReadWriteMemory = 0x00000100
MiniDumpWithoutOptionalData = 0x00000200
MiniDumpWithFullMemoryInfo = 0x00000400
MiniDumpWithThreadInfo = 0x00000800
MiniDumpWithCodeSegs = 0x00001000

# Load dbghelp.dll (which contains MiniDumpWriteDump)
dbghelp = ctypes.windll.dbghelp


# Exception and Context structures (for generating a minidump)
class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [("ExceptionRecord", ctypes.c_ulong), ("ContextRecord", ctypes.c_ulong)]


class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulong),
        ("Dr1", ctypes.c_ulong),
        ("Dr2", ctypes.c_ulong),
        ("Dr3", ctypes.c_ulong),
        ("Dr6", ctypes.c_ulong),
        ("Dr7", ctypes.c_ulong),
        ("FloatSave", ctypes.c_byte * 512),
        ("SegGs", ctypes.c_ulong),
        ("SegFs", ctypes.c_ulong),
        ("SegEs", ctypes.c_ulong),
        ("SegDs", ctypes.c_ulong),
        ("Edi", ctypes.c_ulong),
        ("Esi", ctypes.c_ulong),
        ("Ebx", ctypes.c_ulong),
        ("Edx", ctypes.c_ulong),
        ("Ecx", ctypes.c_ulong),
        ("Eax", ctypes.c_ulong),
        ("Ebp", ctypes.c_ulong),
        ("Eip", ctypes.c_ulong),
        ("SegCs", ctypes.c_ulong),
        ("EFlags", ctypes.c_ulong),
        ("Esp", ctypes.c_ulong),
        ("SegSs", ctypes.c_ulong),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


# Function to write minidump
def write_minidump(exception_type, exception_value, tb):
    dump_dir = os.path.join(os.getenv("LOCALAPPDATA"), "CrashDumps")
    os.makedirs(dump_dir, exist_ok=True)

    # Generate the dump file path with a unique timestamp and process ID
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dump_file = os.path.join(dump_dir, f"AFSUtility.{timestamp}.dmp")

    # Log the exception details
    logging.error("Uncaught exception: %s", exception_value)
    logging.error(
        "Stack trace:\n%s",
        "".join(traceback.format_exception(exception_type, exception_value, tb)),
    )

    # Set up the EXCEPTION_POINTERS and CONTEXT structures
    exception_info = EXCEPTION_POINTERS()
    context_info = CONTEXT()

    try:
        # Open the dump file for writing
        with open(dump_file, "wb") as dump_file_handle:
            # Call MiniDumpWriteDump to generate the minidump
            result = dbghelp.MiniDumpWriteDump(
                ctypes.windll.kernel32.GetCurrentProcess(),
                os.getpid(),
                dump_file_handle.fileno(),
                MiniDumpWithDataSegs
                | MiniDumpWithFullMemory
                | MiniDumpWithProcessThreadData,
                ctypes.byref(exception_info),
                ctypes.byref(context_info),
                None,
            )

            # Check if the dump was written successfully
            if result == 0:
                logging.error(
                    f"Failed to create minidump. Error code: {ctypes.windll.kernel32.GetLastError()}"
                )
            else:
                logging.info(f"Minidump successfully created at: {dump_file}")
    except Exception as e:
        logging.error(f"Failed to write crash dump: {e}")
        logging.error("Error while creating minidump.")


# Install the custom exception handler
def install_exception_handler():
    sys.excepthook = write_minidump


def restart_application():
    """Restarts the application using subprocess for automated recovery."""
    try:
        logging.info("Restarting application...")
        safe_args = [shlex.quote(arg) for arg in sys.argv]
        subprocess.Popen([sys.executable] + safe_args)
        sys.exit(0)  # Close the current instance after starting a new one
    except Exception as e:
        logging.error(f"Failed to restart application: {e}")
        messagebox.showerror(
            "Restart Failed",
            "Could not restart the application. Please restart manually.",
        )


def handle_critical_error(error):
    """Handle critical error and restart if needed."""
    logging.critical(f"Critical error encountered: {error}")
    response = messagebox.askyesno(
        "Critical Error",
        "The application encountered a critical error.\nWould you like to restart?",
    )
    if response:
        restart_application()
    else:
        sys.exit(1)


def run_as_admin():
    """Attempt to re-launch the application with elevated privileges."""
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logging.info("Requesting admin privileges to continue.")
            # Use ShellExecuteW to launch the application with the runas verb
            params = " ".join(
                sys.argv[1:]
            )  # Pass only arguments (not the script itself)
            executable = sys.executable
            result = ctypes.windll.shell32.ShellExecuteW(
                None,  # Parent window (None for no parent)
                "runas",  # Verb indicating elevation
                executable,  # Program to run
                params,  # Command-line parameters
                None,  # Working directory (None for default)
                1,  # Show window (1 for normal, 0 for hidden)
            )
            if result <= 32:
                raise Exception(f"ShellExecuteW failed with error code: {result}")
            sys.exit(0)  # Exit current process after launching the new one
        else:
            logging.info("Already running with admin privileges.")
    except Exception as e:
        logging.error(f"Failed to run as admin: {e}")
        messagebox.showerror(
            "Admin Privileges Required",
            "Could not acquire administrator privileges. Please try again manually.",
        )


def register_file_association():
    """Register .afs file association on Windows with admin privilege check and confirmation messages."""
    if sys.platform != "win32":
        logging.warning("File association is only supported on Windows.")
        return

    # Check for admin privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # Show message and attempt to relaunch with admin privileges
        response = messagebox.askyesno(
            "Admin Privileges Required",
            "Admin privileges are required to register file associations.\n"
            "Would you like to restart this program as an administrator?",
        )
        if response:
            # Relaunch with admin privileges
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)  # Exit the current instance
        else:
            # If user declines admin escalation, exit the function
            messagebox.showinfo(
                "File Association",
                "File association requires admin privileges. Please try again as an administrator.",
            )
            return

    # Admin privileges confirmed, proceed with file association registration
    executable_path = os.path.abspath(sys.executable)
    logging.info(f"Executable Path: {executable_path}")

    # Define registry paths and values
    reg_paths = [
        (r"Software\Classes\.afs", "", "AFSUtility.File"),
        (r"Software\Classes\AFSUtility.File", "", "AFS Utility File"),
        (r"Software\Classes\AFSUtility.File\DefaultIcon", "", f"{executable_path},0"),
        (
            r"Software\Classes\AFSUtility.File\shell\open\command",
            "",
            f'"{executable_path}" "%1"',
        ),
    ]

    try:
        # Set registry keys for file association
        for path, name, value in reg_paths:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                logging.info(f"Set registry value: {path} -> {value}")

        # Success message after successful registration
        messagebox.showinfo(
            "File Association",
            "File association for .afs files has been successfully registered.",
        )
        logging.info("File association registered successfully.")

    except Exception as e:
        logging.error(f"Failed to register file association: {e}")
        messagebox.showerror(
            "File Association Error",
            "Unable to complete file association setup. Please check permissions or try again.",
        )


class AFSUtility:
    def __init__(self, root):
        self.root = root
        self.root.title("AFS Utility")
        self.config_path = os.path.join(
            os.getenv("LOCALAPPDATA"), "WCG847", "AFS Utility", "config", "config.json"
        )
        self.active_threads = []
        self.lock = threading.Lock()
        # Initialise default settings
        self.settings = {
            "theme": "light",  # default theme
            "font": "Helvetica",  # default font
        }

        # Try loading settings from the config file
        self.load_settings()

        # Apply theme and font
        self.apply_theme_and_font()

        # Determine the base directory dynamically
        if getattr(sys, "frozen", False):
            # If running as a compiled bundle, use the temporary path provided by PyInstaller
            base_dir = sys._MEIPASS
        else:
            # If running as a script, use the directory where the script is located
            base_dir = os.path.dirname(os.path.abspath(__file__))

        # Set icon path relative to the base directory
        icon_path = os.path.join(base_dir, "AFS_Utility.ico")

        # Set the window icon
        self.root.iconbitmap(icon_path)

        # Ensure the application runs with admin privileges
        run_as_admin()

        # Set up exception handler for uncaught exceptions
        install_exception_handler()

        # Set up search bar at the top
        self.setup_search_bar()

        # Initialize AFS data storage
        self.toc_entries = []
        self.file_names = []
        self.descriptions = {}
        self.file_count = 0
        self.afs_path = None

        # Sort tracking
        self.sort_column = None
        self.sort_ascending = True

        # Treeview widget with scrollbar
        self.tree_frame = tk.Frame(root)
        self.tree_frame.pack(fill="both", expand=True)

        # Create a Treeview with vertical scrollbar, with "name" as the first column
        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=(
                "name",
                "pointer",
                "size",
                "Creation Date",
                "comments",
                "checksum",
            ),
            show="headings",
        )

        # Define headings and specify new "Checksum" column
        for col in ("name", "pointer", "size", "Creation Date", "comments", "checksum"):
            self.tree.heading(
                col, text=col.capitalize(), command=partial(self.sort_by_column, col)
            )

        self.tree.column("name", width=200)
        self.tree.column("pointer", width=100)
        self.tree.column("size", width=100)
        self.tree.column("Creation Date", width=150)
        self.tree.column("comments", width=200)
        self.tree.column("checksum", width=300)

        self.scrollbar = ttk.Scrollbar(
            self.tree_frame, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscroll=self.scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

        # Bind double-click on "comments" to edit comments
        self.tree.bind("<Double-1>", self.on_double_click)

        # Context menu for right-click options
        self.context_menu = tk.Menu(root, tearoff=0)
        self.context_menu.add_command(
            label="Extract Selected File", command=self.extract_selected_file
        )
        self.context_menu.add_command(
            label="Inject into Selected File", command=self.inject_file
        )
        self.context_menu.add_command(
            label="Delete Selected File", command=self.delete_file
        )
        self.context_menu.add_command(
            label="Upload Description.json", command=self.upload_description_json
        )

        self.current_playback_process = None  # Track the current playback process
        self.is_playing = False  # Track playback state

        # Initialise GUI elements for waveform display and progress bar
        self.waveform_label = Label(root)
        self.waveform_label.pack()

        # Label to display numerical progress
        self.duration_label = Label(root, text="00:00 / 00:00")
        self.duration_label.pack()

        self.context_menu.add_command(label="Play", command=self.play_selected_file)
        self.context_menu.add_command(
            label="Convert", command=self.convert_selected_file
        )

        # Bind Ctrl+P to play sound
        root.bind("<Control-p>", lambda event: self.play_selected_file())

        # Bind application exit to cleanup function
        root.protocol("WM_DELETE_WINDOW", self.on_exit)

        # Binding right-click key
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Menu for file, tools, and help options
        self.menu = tk.Menu(root)
        root.config(menu=self.menu)

        file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open", command=self.load_afs_file)
        file_menu.add_command(label="Create", command=self.create_new_afs_archive)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)

        tools_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Add", command=self.add_file)
        tools_menu.add_command(label="Mass Extract", command=self.mass_extract)
        tools_menu.add_command(
            label="Register File Association", command=register_file_association
        )

        pref_menu = tk.Menu(self.menu, tearoff=0)
        pref_menu.add_command(label="Settings", command=self.pref_display)
        self.menu.add_cascade(label="Preferences", menu=pref_menu)

        help_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(
            label="About AFS Utility",
            command=lambda: self.about_display(
                "About AFS Utility",
                "Welcome to the AFS Utility, a powerful and user-friendly tool designed for managing AFS (Archive File System) files.",
            ),
        )
        help_menu.add_command(
            label="About WCG847",
            command=lambda: self.about_display(
                "About WCG847",
                "WCG847 is a reverse engineer, and modder. He specialises in WWE games and has taken an interest since 2016.",
            ),
        )

        # Initialise last heartbeat timestamp
        self.last_heartbeat = time.time()

        # Start monitoring application health in a separate thread
        monitoring_thread = threading.Thread(target=self.watchdog, daemon=True)
        monitoring_thread.start()

        # Check if a file path is provided as a command-line argument and load it
        if len(sys.argv) > 1 and sys.argv[1].endswith(".afs"):
            self.load_afs_file(sys.argv[1])

    # Add calls to handle_critical_error in relevant try-except blocks
    def monitor_and_adjust_priority(self):
        try:
            p = psutil.Process()
            while True:
                cpu_usage = p.cpu_percent(interval=1)
                if cpu_usage < 10:
                    set_process_priority("IDLE")
                elif 10 <= cpu_usage < 30:
                    set_process_priority("BELOW_NORMAL")
                elif 30 <= cpu_usage < 60:
                    set_process_priority("NORMAL")
                elif 60 <= cpu_usage < 80:
                    set_process_priority("ABOVE_NORMAL")
                else:
                    set_process_priority("HIGH")
                logging.info(f"CPU usage: {cpu_usage}% - Priority adjusted.")
                time.sleep(5)
        except Exception as e:
            handle_critical_error(e)

    def update_heartbeat(self):
        """Update the heartbeat timestamp periodically, even if there is no user input."""
        self.last_heartbeat = time.time()
        logging.debug("Heartbeat updated.")

    def watchdog(self):
        """Monitor the application's health, distinguishing between lockup and inactivity."""
        max_inactive_duration = 300  # 5 minutes
        while True:
            time.sleep(10)
            time_since_last_heartbeat = time.time() - self.last_heartbeat
            if time_since_last_heartbeat > max_inactive_duration:
                logging.warning(
                    f"No heartbeat detected in {time_since_last_heartbeat} seconds. "
                    "Application may be unresponsive."
                )
                # Instead of automatic recovery, ask the user
                self.ask_for_manual_recovery()
            else:
                logging.debug("Application heartbeat is active.")
    
    def ask_for_manual_recovery(self):
        response = messagebox.askyesno(
            "Application Not Responding",
            "It seems the application has stopped responding. Do you want to attempt recovery?"
        )
        if response:
            self.attempt_recovery()



    def is_healthy(self):
        return self.afs_path is not None and self.tree.get_children()

    def attempt_recovery(self):
        try:
            if self.afs_path:
                with open(self.afs_path, "rb") as afs_file:
                    self.parse_afs(afs_file)
                messagebox.showinfo("Recovery", "Application recovered successfully.")
        except Exception as e:
            handle_critical_error(e)

    def run_in_thread(self, target, *args, timeout=None, max_retries=1):
        """
        Runs a target function in a new thread with enhanced lifecycle management.

        Parameters:
        - target: Callable to execute in the thread.
        - args: Positional arguments for the target function.
        - timeout: Maximum allowed time for the thread to complete (in seconds). Default is None (no timeout).
        - max_retries: Maximum number of times to retry in case of failure. Default is 1.
        """

        def thread_wrapper():
            nonlocal retries
            try:
                logging.info(f"Thread started for {target.__name__} with args: {args}")
                retries = 0
                while retries <= max_retries:
                    start_time = time.time()
                    try:
                        target(*args)
                        break  # Exit loop if successful
                    except Exception as e:
                        retries += 1
                        logging.error(
                            f"Error in thread ({target.__name__}): {e}. Retrying {retries}/{max_retries}"
                        )
                        if retries > max_retries:
                            raise
                        time.sleep(2)  # Backoff before retrying

                    # Timeout enforcement
                    elapsed_time = time.time() - start_time
                    if timeout and elapsed_time > timeout:
                        logging.error(
                            f"Thread {target.__name__} timed out after {timeout} seconds."
                        )
                        raise TimeoutError(
                            f"Execution of {target.__name__} exceeded timeout."
                        )
                else:
                    logging.info(
                        f"Thread for {target.__name__} completed successfully."
                    )

            except Exception as e:
                logging.error(f"Thread {target.__name__} failed: {e}")

            finally:
                with self.lock:
                    self.active_threads.remove(thread)
                logging.info(f"Thread for {target.__name__} ended.")

        # Create and track the thread
        retries = 0
        thread = threading.Thread(
            target=thread_wrapper, daemon=True
        )  # Daemon thread to ensure it exits with the main program
        with self.lock:
            self.active_threads.append(thread)
        thread.start()
        logging.info(f"Thread {thread.name} started for target {target.__name__}.")

    def pref_display(self):
        # Create a new window for preferences
        pref_window = tk.Toplevel(self.root)
        pref_window.title("Preferences")

        # Theme selection
        theme_label = tk.Label(pref_window, text="Select Theme:")
        theme_label.grid(row=0, column=0, padx=10, pady=10)

        theme_var = tk.StringVar(value=self.settings["theme"])
        light_theme_rb = tk.Radiobutton(
            pref_window, text="Light", variable=theme_var, value="light"
        )
        dark_theme_rb = tk.Radiobutton(
            pref_window, text="Dark", variable=theme_var, value="dark"
        )

        light_theme_rb.grid(row=0, column=1, padx=10, pady=10)
        dark_theme_rb.grid(row=0, column=2, padx=10, pady=10)

        # Font selection
        font_label = tk.Label(pref_window, text="Select Font:")
        font_label.grid(row=1, column=0, padx=10, pady=10)

        font_list = list(tkfont.families())
        font_var = tk.StringVar(value=self.settings["font"])
        font_menu = ttk.Combobox(
            pref_window, textvariable=font_var, values=font_list, state="readonly"
        )
        font_menu.grid(row=1, column=1, padx=10, pady=10)

        # Save button
        save_button = tk.Button(
            pref_window,
            text="Save",
            command=lambda: self.save_preferences(
                theme_var.get(), font_var.get(), pref_window
            ),
        )
        save_button.grid(row=2, column=0, columnspan=3, pady=20)

    def save_preferences(self, theme, font, window):
        # Update settings in memory
        self.settings["theme"] = theme
        self.settings["font"] = font

        # Ensure directory for config path exists
        config_dir = os.path.dirname(self.config_path)
        try:
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
                logging.debug(f"Created directory for config at {config_dir}")
        except Exception as e:
            logging.error(f"Failed to create directory for config: {e}")
            messagebox.showerror("Error", f"Failed to create directory: {e}")
            return

        # Save settings to config.json
        try:
            with open(self.config_path, "w") as config_file:
                json.dump(self.settings, config_file, indent=4)
            logging.info(f"Settings saved to {self.config_path}")
        except Exception as e:
            logging.error(f"Failed to save settings: {e}")
            messagebox.showerror("Error", f"Failed to save settings: {e}")
            return

        # Apply changes and close preferences window
        self.apply_theme_and_font()
        window.destroy()
        messagebox.showinfo("Settings Saved", "Your preferences have been saved.")

    def apply_theme_and_font(self):
        # Apply the selected theme and font
        if self.settings["theme"] == "dark":
            self.root.configure(bg="black")
            self.root.option_add("*foreground", "white")
            self.root.option_add("*background", "black")
        else:
            self.root.configure(bg="white")
            self.root.option_add("*foreground", "black")
            self.root.option_add("*background", "white")

        # Apply selected font to the whole window
        font = (self.settings["font"], 10)
        self.root.option_add("*font", font)

    def load_settings(self):
        # Load settings from config.json if it exists
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as config_file:
                    self.settings = json.load(config_file)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load settings: {e}")

    def on_exit(self):
        """Ensure playback stops on exit."""
        self.stop_playback()
        self.root.quit()

    def stop_playback(self):
        """Stop the current playback process if running."""
        if (
            self.current_playback_process
            and self.current_playback_process.poll() is None
        ):
            self.current_playback_process.terminate()
            logging.info("Stopped playback process")
            self.current_playback_process = None
            self.is_playing = False

    def extract_file_to_temp(self, file_name, file_data):
        """Extracts a file to a temp directory with its original extension."""
        temp_dir = tempfile.mkdtemp()
        _, ext = os.path.splitext(file_name)
        temp_file_path = os.path.join(temp_dir, f"audiofile{ext}")

        with open(temp_file_path, "wb") as temp_file:
            temp_file.write(file_data)

        return temp_file_path

    def get_audio_duration(self, file_path):
        """Extract the duration of an audio file using ffprobe."""
        try:
            result = subprocess.run(
                [
                    "ffprobe",
                    "-v",
                    "error",
                    "-show_entries",
                    "format=duration",
                    "-of",
                    "default=noprint_wrappers=1:nokey=1",
                    file_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                startupinfo=self.get_hidden_startupinfo(),
            )
            duration = float(result.stdout.strip())
            return duration
        except Exception as e:
            logging.error(f"Error getting audio duration: {e}")
            return None

    def get_hidden_startupinfo(self):
        """Returns startup info to hide console window on Windows."""
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return startupinfo

    def generate_waveform(self, file_path):
        """Generates a waveform image using ffmpeg and returns the image path."""
        temp_dir = tempfile.mkdtemp()
        waveform_path = os.path.join(temp_dir, "waveform.png")

        try:
            subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-i",
                    file_path,
                    "-filter_complex",
                    "aformat=channel_layouts=mono,showwavespic=s=600x120",
                    "-frames:v",
                    "1",
                    waveform_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=self.get_hidden_startupinfo(),
            )
            return waveform_path
        except Exception as e:
            logging.error(f"Error generating waveform: {e}")
            return None

    def display_waveform(self, waveform_path):
        """Display the waveform image in the GUI."""
        try:
            waveform_image = Image.open(waveform_path)
            waveform_photo = ImageTk.PhotoImage(waveform_image)
            self.waveform_label.config(image=waveform_photo)
            self.waveform_label.image = waveform_photo
        except Exception as e:
            logging.error(f"Error displaying waveform: {e}")

    def play_selected_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected.")
            return
        file_index = self.tree.index(selected_item[0])
        pointer, size = self.toc_entries[file_index]
        file_name = self.file_names[file_index]

        # Stop any existing playback before starting a new one
        self.stop_playback()

        # Extract file to temporary directory with correct extension
        file_data = self.read_from_afs_file(pointer, size)
        temp_file_path = self.extract_file_to_temp(file_name, file_data)
        if temp_file_path is None:
            return

        # Get audio duration and generate waveform for the GUI
        duration = self.get_audio_duration(temp_file_path)
        waveform_path = self.generate_waveform(temp_file_path)
        if waveform_path:
            self.display_waveform(waveform_path)

        # Determine whether to play as video (SFD) or audio (ADX)
        if self.is_sfd_file(temp_file_path):
            self.play_video(temp_file_path)
        else:
            self.play_audio(temp_file_path)

    def is_sfd_file(self, file_path):
        """Determine if a file is an SFD video file based on the extension."""
        return file_path.lower().endswith(".sfd")

    def play_audio(self, file_path):
        """Play an audio file with ffplay, ensuring non-blocking playback."""
        command = ["ffplay", "-nodisp", "-autoexit", file_path]
        logging.info(f"Running audio command: {' '.join(command)}")

        def audio_playback():
            try:
                self.is_playing = True
                self.current_playback_process = subprocess.Popen(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,  # Avoid blocking on stderr
                    startupinfo=self.get_hidden_startupinfo(),
                )
                self.current_playback_process.wait()
            except Exception as e:
                logging.error(f"Error during audio playback: {e}")
            finally:
                self.is_playing = False
                shutil.rmtree(os.path.dirname(file_path), ignore_errors=True)
                logging.info("Audio playback finished and temp files cleaned up")

        # Start playback in a separate thread
        threading.Thread(target=audio_playback, daemon=True).start()

    def play_video(self, file_path):
        """Play a video file using ffplay with a scaled window size based on the user's screen dimensions."""

        # Fetch screen dimensions using tkinter
        root = tk.Tk()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        root.destroy()

        # Calculate 80% of the screen dimensions
        window_width = int(screen_width * 0.8)
        window_height = int(screen_height * 0.8)

        # ffplay command with specified window size
        command = [
            "ffplay",
            file_path,
            "-x",
            str(window_width),
            "-y",
            str(window_height),
        ]
        logging.info(
            f"Running video command with custom window size: {' '.join(command)}"
        )

        def video_playback():
            try:
                # Launch ffplay with only stdout and stderr suppressed to keep the video GUI visible
                self.current_playback_process = subprocess.Popen(
                    command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                self.current_playback_process.wait()
            except Exception as e:
                logging.error(f"Error during video playback: {e}")
            finally:
                # Clean up the temporary video file
                shutil.rmtree(os.path.dirname(file_path), ignore_errors=True)
                logging.info("Video playback finished and temp files cleaned up")

        # Start playback in a separate thread to prevent blocking the main thread
        threading.Thread(target=video_playback, daemon=True).start()

    def convert_selected_file(self):
        """Convert selected file based on its type (ADX to WAV, SFD to MP4)."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected.")
            return
        file_index = self.tree.index(selected_item[0])
        pointer, size = self.toc_entries[file_index]
        file_name = self.file_names[file_index]

        # Extract file to temporary directory with correct extension
        file_data = self.read_from_afs_file(pointer, size)
        temp_file_path = self.extract_file_to_temp(file_name, file_data)
        if temp_file_path is None:
            return

        # Determine conversion parameters based on file type
        if self.is_sfd_file(temp_file_path):
            save_ext = ".mp4"
            conversion_args = [
                "ffmpeg",
                "-i",
                temp_file_path,
                "-c:v",
                "libx264",
                "-preset",
                "slow",
                "-crf",
                "18",
            ]
        else:
            save_ext = ".wav"
            conversion_args = ["ffmpeg", "-i", temp_file_path]

        # Prompt user for save location with appropriate extension
        save_path = filedialog.asksaveasfilename(
            defaultextension=save_ext,
            filetypes=[(f"{save_ext.upper()} files", f"*{save_ext}")],
        )
        if not save_path:
            shutil.rmtree(os.path.dirname(temp_file_path), ignore_errors=True)
            return

        # Execute conversion and handle errors
        conversion_args.append(save_path)
        logging.info(f"Running conversion command: {' '.join(conversion_args)}")
        try:
            result = subprocess.run(
                conversion_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=self.get_hidden_startupinfo(),
                check=True,
            )
            logging.debug(f"ffmpeg output: {result.stdout.decode().strip()}")
            if result.stderr:
                logging.error(f"ffmpeg error: {result.stderr.decode().strip()}")
            messagebox.showinfo(
                "Conversion Complete", f"File converted successfully to {save_path}"
            )
        except subprocess.CalledProcessError as e:
            logging.error(f"Conversion error: {e}")
            messagebox.showerror("Conversion Error", f"Failed to convert file: {e}")
        finally:
            shutil.rmtree(os.path.dirname(temp_file_path), ignore_errors=True)

    def create_new_afs_archive(self):
        # Start the archive creation in a separate thread
        self.run_in_thread(self._create_new_afs_archive)

    def _create_new_afs_archive(self):
        """Creates a new AFS archive, ensuring only files with valid magic headers are included, with optimisations for speed."""
        folder_path = filedialog.askdirectory(
            title="Select Folder with Files for New AFS Archive"
        )
        if not folder_path:
            logging.info("No folder selected for AFS archive creation.")
            return

        # Log the folder contents
        logging.debug(f"Selected folder: {folder_path}")
        logging.debug(f"Folder contents: {os.listdir(folder_path)}")

        # Allowed magic headers for CRI Middleware compliance
        allowed_headers = {b"\x80\x00", b"\x00\x00"}
        invalid_files = []

        # Optimise with buffered I/O for all files
        logging.info("Verifying files for valid headers.")
        for file_name in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file_name)
            if os.path.isfile(file_path):
                with open(file_path, "rb") as file:
                    header = file.read(2)
                    if header not in allowed_headers:
                        invalid_files.append(file_name)

        # If invalid files are detected, stop the process and notify the user
        if invalid_files:
            logging.error(
                f"Invalid files detected: {', '.join(invalid_files)}. Only files with valid headers are allowed."
            )
            messagebox.showerror(
                "Invalid Files Found",
                f"The following files do not have valid ADX or SFD magic headers:\n{', '.join(invalid_files)}"
                "\n\nOnly files with headers matching ADX (0x80 0x00) or SFD (0x00 0x00) are allowed.",
            )
            return

        output_file = filedialog.asksaveasfilename(
            title="Save New AFS Archive As",
            defaultextension=".afs",
            filetypes=[("CRIWare Archive File System", "*.afs")],
        )
        if not output_file:
            logging.info("AFS archive creation canceled by user.")
            return

        logging.info(f"Creating new AFS archive at: {output_file}")

        # Collect file paths and prepare TOC entries
        file_paths = [
            os.path.join(folder_path, f)
            for f in os.listdir(folder_path)
            if os.path.isfile(os.path.join(folder_path, f))
        ]
        toc_entries = []
        file_names = []
        file_data = []
        pointer = 0x800  # Start data section after 0x800 offset for the header

        logging.info("Gathering file data and creating TOC entries.")

        # Step 1: Create TOC and store file data in memory
        for i, file_path in enumerate(file_paths):
            logging.info(f"Processing file {i + 1}/{len(file_paths)}: {file_path}")
            with open(file_path, "rb") as f:
                data = f.read()
                size = len(data)
                toc_entries.append((pointer, size))
                file_data.append(data)
                file_names.append(os.path.basename(file_path).ljust(32, "\x00"))
                pointer += (size + 0x7FF) & ~0x7FF  # Align to next 0x800 boundary
                logging.info("TOC entries prepared successfully.")

        # Step 2: Calculate footer pointer based on last file's data
        footer_pointer = pointer
        toc_entries.append(
            (footer_pointer, 0x20)
        )  # Append footer as "last listing" in TOC

        footer_entries = []
        for name, (file_pointer, file_size) in zip(file_names, toc_entries):
            # Capture metadata: filename, creation date, and TOC entries
            creation_date = datetime.datetime.now()
            footer_entries.append(
                {
                    "name": name,
                    "pointer": file_pointer,
                    "size": file_size,
                    "creation_date": creation_date,
                }
            )

        # Step 3: Write TOC and file data in batches with memory mapping
        try:
            logging.info("Writing AFS archive to file.")
            with open(output_file, "wb") as afs_file:
                # Write the AFS magic bytes and file count
                afs_file.write(b"AFS\x00")
                afs_file.write(
                    struct.pack("<I", len(file_paths))
                )  # Exclude footer from file count

                for toc_entry in toc_entries:
                    afs_file.write(struct.pack("<II", *toc_entry))

                # Pad TOC to reach 0x800 offset for the data section
                current_pos = afs_file.tell()
                if current_pos < 0x800:
                    afs_file.write(b"\x00" * (0x800 - current_pos))

                # Write file data with padding
                for data in file_data:
                    afs_file.write(data)
                    afs_file.write(b"\x00" * ((0x800 - len(data) % 0x800) % 0x800))

                # Align footer block to 2048-byte boundary
                current_pos = afs_file.tell()
                afs_file.write(b"\x00" * ((0x800 - current_pos % 0x800) % 0x800))

                # Write footer with metadata (filenames, dates, pointers, sizes)
                for entry in footer_entries:
                    afs_file.write(entry["name"].encode("latin1"))
                    afs_file.write(struct.pack("<H", entry["creation_date"].year))
                    afs_file.write(struct.pack("<H", entry["creation_date"].month))
                    afs_file.write(struct.pack("<H", entry["creation_date"].day))
                    afs_file.write(struct.pack("<H", entry["creation_date"].hour))
                    afs_file.write(struct.pack("<H", entry["creation_date"].minute))
                    afs_file.write(struct.pack("<H", entry["creation_date"].second))
                    afs_file.write(struct.pack("<I", entry["size"]))

                # Final padding and copyright footer
                current_pos = afs_file.tell()
                afs_file.write(b"\x00" * ((0x800 - current_pos % 0x800) % 0x800))
                afs_file.write("© 2024 AFS Utility".ljust(32, "\x00").encode("latin1"))

                # Final file alignment
                current_pos = afs_file.tell()
                afs_file.write(b"\x00" * ((0x800 - current_pos % 0x800) % 0x800))

            logging.info("New AFS archive created successfully.")
            self.root.after(
                0,
                lambda: messagebox.showinfo(
                    "Success", "New AFS archive created successfully."
                ),
            )

        except Exception as e:
            logging.error(f"Failed to create AFS archive: {e}")
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Error", f"Failed to create AFS archive: {e}"
                ),
            )

    def mass_extract(self):
        self.run_in_thread(self._mass_extract)

    def _mass_extract(self):
        """Extract all files in the AFS to a selected directory (runs in a background thread)."""
        if not self.afs_path:
            self.root.after(
                0, lambda: messagebox.showwarning("Warning", "No AFS file loaded.")
            )
            return

        directory = filedialog.askdirectory(
            title="Select Directory for Mass Extraction"
        )
        if not directory:
            return

        def extract_files():
            try:
                for idx in range(self.file_count):
                    pointer, size = self.toc_entries[idx]
                    file_name = self.file_names[idx]
                    file_data = self.read_from_afs_file(pointer, size)
                    file_path = os.path.join(directory, file_name)

                    with open(file_path, "wb") as output_file:
                        output_file.write(file_data)

                self.root.after(
                    0,
                    lambda: messagebox.showinfo(
                        "Success", "All files extracted successfully."
                    ),
                )

            except Exception as e:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Error", f"Failed to extract files: {e}"
                    ),
                )

        self.run_in_thread(extract_files)

    def load_afs_file(self, afs_path=None):
        """Load an AFS file with graceful degradation on error."""
        if not afs_path:
            afs_path = filedialog.askopenfilename(
                title="Select File",
                filetypes=[("CRIWare Archive File System", "*.afs")],
            )

        if afs_path:
            self.afs_path = afs_path  # Store the AFS path for later usage
            try:
                self.load_description_json()  # Attempt to load description.json
                with open(self.afs_path, "rb") as afs_file:
                    self.parse_afs(afs_file)
            except FileNotFoundError:
                messagebox.showerror(
                    "File Not Found", "The selected file does not exist."
                )
                logging.error("AFS file not found.")
            except PermissionError:
                messagebox.showerror(
                    "Permission Denied",
                    "Cannot access the file due to permission issues.",
                )
                logging.error("Permission denied while accessing AFS file.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load AFS file: {e}")
                logging.error(f"Failed to load AFS file: {e}")

    def load_description_json(self):
        """Load descriptions from description.json if it exists."""
        appdata_dir = os.getenv("LOCALAPPDATA") + "\\WCG847\\AFS Utility"
        description_path = os.path.join(appdata_dir, "description.json")

        if os.path.exists(description_path):
            try:
                with open(description_path, "r") as json_file:
                    self.descriptions = json.load(json_file)
            except Exception as e:
                messagebox.showwarning("Warning", f"Could not load descriptions: {e}")

    # Method to compute crc32 checksum
    def compute_crc32_checksum(self, file_data):
        """Compute CRC32 checksum for the provided file data."""
        return f"{zlib.crc32(file_data) & 0xFFFFFFFF:08x}"  # Ensure the result is in hexadecimal format.

    def parse_afs(self, afs_file):
        try:
            # Clear previous entries
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Verify and parse the AFS header
            header = afs_file.read(4)
            if header[:3] != b"AFS" or header[3] != 0x00:
                messagebox.showerror(
                    "Invalid Format", "The file is not a valid CRIWare archive."
                )
                return

            # Number of files in AFS
            self.file_count = struct.unpack("<I", afs_file.read(4))[0]

            # Start of TOC
            self.toc_entries = []
            for _ in range(self.file_count):
                pointer = struct.unpack("<I", afs_file.read(4))[0]
                size = struct.unpack("<I", afs_file.read(4))[0]
                self.toc_entries.append((pointer, size))

            # Calculate expected footer start location
            last_entry_pointer, last_entry_size = self.toc_entries[-1]
            expected_footer_start = last_entry_pointer + last_entry_size

            # Align to nearest 0x800 (2048) boundary if necessary
            if expected_footer_start % 0x800 != 0:
                aligned_footer_start = (expected_footer_start + 0x800) & ~0x7FF
                logging.info(
                    f"Non-aligned footer detected. Aligning to nearest 0x800 boundary."
                )
                logging.info(f"Adjusted footer start: 0x{aligned_footer_start:X}")
                expected_footer_start = aligned_footer_start
            else:
                logging.info(f"Footer is already aligned at: 0x{expected_footer_start:X}")

            afs_file.seek(expected_footer_start)

            # File names, dates, and sizes storage
            self.file_names = []
            self.file_dates = []  # List to store parsed dates
            self.file_sizes = []  # List to store parsed file sizes

            default_date = datetime.datetime(1970, 1, 1, 0, 0, 0)  # Define default date

            for _ in range(self.file_count):
                # File name parsing
                name = afs_file.read(0x20).decode("latin1").strip("\x00")
                self.file_names.append(name)

                try:
                    # Read the creation date (formatted as YYMMDDHHMMSS in 2 bytes each)
                    year = struct.unpack("<H", afs_file.read(2))[0]
                    month = struct.unpack("<H", afs_file.read(2))[0]
                    day = struct.unpack("<H", afs_file.read(2))[0]
                    hour = struct.unpack("<H", afs_file.read(2))[0]
                    minute = struct.unpack("<H", afs_file.read(2))[0]
                    second = struct.unpack("<H", afs_file.read(2))[0]

                    # Attempt to create a date object, defaulting to the specified date if invalid
                    file_date = datetime.datetime(year, month, day, hour, minute, second)
                except (ValueError, OverflowError):
                    # If an error occurs, use the default date
                    logging.warning(f"Invalid date for file '{name}', using default date.")
                    file_date = default_date

                self.file_dates.append(file_date.strftime("%Y-%m-%d %H:%M:%S"))

                # Read 4-byte file size
                file_size = struct.unpack("<I", afs_file.read(4))[0]
                self.file_sizes.append(file_size)

            # Log parsed dates and sizes
            logging.info(f"Parsed file dates: {self.file_dates}")
            logging.info(f"Parsed file sizes: {self.file_sizes}")

            # Verify file names were parsed correctly
            if len(self.file_names) != self.file_count:
                messagebox.showerror(
                    "Parsing Error",
                    "The number of file names does not match the file count.",
                )
                logging.error(f"The number of file names does not match the file count.")
                return

            # Print the parsed file names for verification
            logging.info(f"Parsed file names: {self.file_names}")

            self.checksums = {}  # Dictionary to hold checksums for ADX/SFD files

            for idx in range(self.file_count):
                pointer, size = self.toc_entries[idx]
                afs_file.seek(pointer)
                file_header = afs_file.read(4)

                allowed_headers = {b"\x80\x00", b"\x00\x00"}
                if file_header[:2] in allowed_headers:
                    # Read full file data for checksum computation
                    afs_file.seek(pointer)
                    file_data = afs_file.read(size)

                    # Compute SHA-512 checksum and store it
                    checksum = self.compute_crc32_checksum(file_data)
                    self.checksums[self.file_names[idx]] = checksum
                else:
                    # If file header is invalid, set checksum to None and log warning
                    checksum = None
                    logging.warning(f"Invalid header for file: {self.file_names[idx]}")

                # Populate Treeview with new column for checksum display
                name = self.file_names[idx]
                formatted_size = self.format_size(size)
                description = self.descriptions.get(name, "")
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        name,
                        str(pointer),
                        formatted_size,
                        self.file_dates[idx],
                        description,
                        checksum,
                    ),
                )

            # Save checksums to local appdata JSON file
            self.save_checksums_to_appdata()

        except Exception as e:
            # Log the critical error, capture the stack trace
            logging.critical(f"Critical error encountered during AFS parsing: {e}", exc_info=True)
            # Optionally, show a message box with the error to the user
            messagebox.showerror("Critical Error", f"An error occurred: {e}")

    

    # Method to save checksums to local appdata JSON
    def save_checksums_to_appdata(self):
        """Save checksums to a JSON file in the AppData directory for persistent storage."""
        appdata_dir = os.path.join(os.getenv("LOCALAPPDATA"), "WCG847", "AFS Utility")
        os.makedirs(appdata_dir, exist_ok=True)
        checksums_path = os.path.join(appdata_dir, "checksums.json")

        try:
            with open(checksums_path, "w") as json_file:
                json.dump(self.checksums, json_file, indent=4)
            logging.info("Checksums saved to AppData successfully.")
        except IOError as e:
            logging.error(f"Failed to save checksums: {e}")

    def format_size(self, size):
        try:
            # Validate input size
            if not isinstance(size, (int, float, Decimal)):
                logging.error(
                    f"Invalid size input: {size}. Expected int, float, or Decimal."
                )
                raise ValueError("Input size must be an integer, float, or Decimal.")

            if size < 0:
                logging.warning(
                    f"Negative size detected: {size}. File sizes cannot be negative."
                )
                raise ValueError("File size cannot be negative.")

            # Handle zero size early
            if size == 0:
                logging.info(f"Zero size detected. Returning 0 B.")
                return "0 B"

            units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
            size = Decimal(size)
            index = 0

            # Detect possible infinite loop or overflow
            if size > Decimal("1e+30"):  # Arbitrary large threshold to prevent overflow
                logging.error(
                    f"Overflow risk detected with size: {size}. Value is too large."
                )
                raise OverflowError(f"Size {size} exceeds safe limit.")

            logging.info(f"Starting size conversion for {size} bytes.")

            # Conversion process with unit shifting
            while size >= 1024 and index < len(units) - 1:
                logging.debug(
                    f"Converting: {size} >= 1024, shifting unit to {units[index + 1]}."
                )
                size /= 1024
                index += 1

            # Watchdog 4: Precision control
            formatted_size = f"{size.quantize(Decimal('0.1'))} {units[index]}"
            logging.info(f"Formatted size: {formatted_size}")

            return formatted_size

        except ValueError as ve:
            logging.error(f"Value error occurred: {ve}")
            raise
        except OverflowError as oe:
            logging.error(f"Overflow error occurred: {oe}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error occurred: {e}")
            raise

    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def read_from_afs_file(self, pointer, size, retries=3):
        """Helper function to read data from the AFS file at a specific pointer with retries for recovery."""
        attempt = 0
        while attempt < retries:
            try:
                with open(self.afs_path, "rb") as afs_file:
                    afs_file.seek(pointer)
                    return afs_file.read(size)
            except IOError as e:
                logging.error(f"Read attempt {attempt+1} failed: {e}")
                attempt += 1
                time.sleep(0.5)  # Wait before retrying
            except Exception as e:
                logging.error(f"Unexpected error while reading from AFS file: {e}")
                raise e  # Raise unexpected errors immediately
        messagebox.showerror(
            "Read Error", "Failed to read data after multiple attempts."
        )
        return None  # Return None if all attempts fail

    def extract_selected_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected.")
            return
        file_index = self.tree.index(selected_item[0])
        pointer, size = self.toc_entries[file_index]
        file_name = self.file_names[file_index]
        save_path = filedialog.asksaveasfilename(
            title="Save Extracted File", initialfile=file_name, defaultextension=".adx"
        )
        if save_path:
            try:
                file_data = self.read_from_afs_file(pointer, size)
                with open(save_path, "wb") as output_file:
                    output_file.write(file_data)
                messagebox.showinfo(
                    "Success", f"File '{file_name}' extracted successfully."
                )
            except IOError as e:
                logging.error(f"IO Error during extraction: {e}")
                messagebox.showerror(
                    "Error", f"Failed to extract file due to I/O error: {e}"
                )
            except Exception as e:
                logging.error(f"Error during extraction: {e}")
                messagebox.showerror("Error", f"Failed to extract file: {e}")

    def on_double_click(self, event):
        """Handle double-click to edit comments."""
        item_id = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)

        # Check if double-click is on the "comments" column (fourth column)
        if column == "#5" and item_id:
            current_comment = self.tree.item(item_id, "values")[3]
            new_comment = simpledialog.askstring(
                "Edit Comment", "Enter your comment:", initialvalue=current_comment
            )

            if new_comment is not None:
                # Update the comment in the tree view
                item_values = list(self.tree.item(item_id, "values"))
                item_values[3] = new_comment
                self.tree.item(item_id, values=item_values)

                # Update descriptions dictionary and save to description.json
                file_name = item_values[0]
                self.descriptions[file_name] = new_comment
                self.save_description_json()

    def save_description_json(self):
        """Save current descriptions to description.json in the required format."""
        appdata_dir = os.path.join(os.getenv("LOCALAPPDATA"), "WCG847", "AFS Utility")
        os.makedirs(appdata_dir, exist_ok=True)
        description_path = os.path.join(appdata_dir, "description.json")

        # Creating a dictionary with the specified structure
        formatted_descriptions = {
            name: self.descriptions.get(name, "") for name in self.file_names
        }

        try:
            with open(description_path, "w") as json_file:
                json.dump(
                    formatted_descriptions, json_file, indent=2
                )  # Use indent for pretty printing
        except IOError as e:
            logging.error(f"Error saving descriptions: {e}")
            messagebox.showerror("Error", f"Failed to save descriptions: {e}")

    def sort_by_column(self, column):
        if self.sort_column == column:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = column
            self.sort_ascending = True

        data = [
            (self.tree.set(item, column), item) for item in self.tree.get_children("")
        ]

        if column in ("pointer", "size"):
            data.sort(
                key=lambda t: (
                    int(t[0].replace("0x", ""), 16) if t[0].startswith("0x") else 0
                ),
                reverse=not self.sort_ascending,
            )
        elif column == "checksum":
            data.sort(key=lambda t: t[0], reverse=not self.sort_ascending)
        else:
            data.sort(reverse=not self.sort_ascending)

        for index, (_, item) in enumerate(data):
            self.tree.move(item, "", index)

        self.tree.heading(
            column, text=f"{column.capitalize()} {'↑' if self.sort_ascending else '↓'}"
        )

    def inject_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected.")
            return
        file_path = filedialog.askopenfilename(title="Select File to Inject")
        if file_path:
            messagebox.showinfo(
                "Not Implemented", "File injection is not fully implemented."
            )

    def delete_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected.")
            return
        file_index = self.tree.index(selected_item[0])
        messagebox.showinfo(
            "Not Implemented", "File deletion is not fully implemented."
        )

    def add_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Add")
        if file_path:
            file_name = simpledialog.askstring(
                "File Name", "Enter a name for the new file (up to 32 chars):"
            )
            if file_name and len(file_name) <= 32:
                messagebox.showinfo(
                    "Not Implemented",
                    "Add file functionality is not fully implemented.",
                )

    def upload_description_json(self):
        messagebox.showinfo(
            "Description Format",
            "The JSON file should have the following format:\n"
            "{\n"
            '  "file_name_1": "Description of file 1",\n'
            '  "file_name_2": "Description of file 2",\n'
            "  ...\n"
            "}",
        )
        json_path = filedialog.askopenfilename(
            title="Select Description.json", filetypes=[("JSON files", "*.json")]
        )
        if json_path:
            try:
                with open(json_path, "r") as json_file:
                    self.descriptions = json.load(json_file)
                # Save to AppData directory
                appdata_dir = os.getenv("LOCALAPPDATA") + "\\WCG847\\AFS Utility"
                os.makedirs(appdata_dir, exist_ok=True)
                with open(
                    os.path.join(appdata_dir, "description.json"), "w"
                ) as appdata_json:
                    json.dump(self.descriptions, appdata_json)
                # Refresh Treeview with new descriptions
                self.refresh_treeview_with_descriptions()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load description JSON: {e}")

    def refresh_treeview_with_descriptions(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx in range(self.file_count - 1):
            pointer, size = self.toc_entries[idx]
            name = self.file_names[idx]
            formatted_size = self.format_size(size)
            description = self.descriptions.get(name, "")
            self.tree.insert(
                "", "end", values=(name, str(pointer), formatted_size, description)
            )

    def setup_search_bar(self):
        # Frame for search bar, placed at the top
        search_frame = tk.Frame(self.root)
        search_frame.pack(fill=tk.X, padx=10, pady=5)

        # Search label
        search_label = tk.Label(search_frame, text="Search:")
        search_label.pack(side=tk.LEFT)

        # Search entry field
        self.search_entry = tk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Bind search entry to search function
        self.search_entry.bind("<KeyRelease>", self.on_search)

    def on_search(self, event):
        search_term = self.search_entry.get().lower()

        # Clear current entries in the Treeview
        self.tree.delete(*self.tree.get_children())

        # Filter based on search term and re-populate the Treeview
        if search_term:
            # Insert only items that match the search term
            for item in self.original_data:
                if (
                    search_term in item[0].lower()
                ):  # Search is based on the 'name' field
                    self.tree.insert("", tk.END, values=item)
        else:
            # If no search term, display all items
            for item in self.original_data:
                self.tree.insert("", tk.END, values=item)

    def about_display(self, title, description):
        about_window = tk.Toplevel()
        about_window.title(title)
        # Grab width and height
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        # Set window size to 80% of screen size
        window_width = int(screen_width * 0.8)
        window_height = int(screen_height * 0.8)

        about_window.geometry(f"{window_width}x{window_height}")

        bold_font = tkfont.Font(family="Helvetica", size=12, weight="bold")

        text_widget = tk.Text(about_window, font=bold_font, wrap=tk.WORD)
        text_widget.insert(tk.END, description)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    app = AFSUtility(root)
    root.resizable(True, True)
    # Grab width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Set window size to 80% of screen size
    window_width = int(screen_width * 0.8)
    window_height = int(screen_height * 0.8)

    root.geometry(f"{window_width}x{window_height}")

    root.mainloop()