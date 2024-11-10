import ctypes
import datetime
import json
import logging
import os
import psutil
import shlex
import struct
import subprocess
import sys
import threading
import time
import traceback

import pywintypes
import win32api
import win32con
import win32process
import win32gui
import winreg

from functools import partial
from decimal import Decimal
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

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


def monitor_and_adjust_priority():
    """Monitor CPU usage and adjust process priority based on workload."""
    p = psutil.Process()  # Current process
    try:
        while True:
            # Get current CPU usage
            cpu_usage = p.cpu_percent(interval=1)

            # Adjust priority based on CPU usage
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
            time.sleep(5)  # Check every 5 seconds

    except psutil.NoSuchProcess:
        logging.error("Process not found.")
    except Exception as e:
        logging.error(f"Error during priority adjustment: {e}")


# Start monitoring in a separate thread so it doesn't block the main application
monitoring_thread = threading.Thread(target=monitor_and_adjust_priority, daemon=True)
monitoring_thread.start()


def write_minidump(exception_type, exception_value, tb):
    """Write a mini-dump to disk when a crash happens."""
    dump_dir = os.path.join(
        os.getenv("LOCALAPPDATA"), "wcg847", "AFS Utility", "crashdumps"
    )
    os.makedirs(dump_dir, exist_ok=True)

    # Construct dump file path with a timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dump_file = os.path.join(dump_dir, f"crash_{timestamp}.dmp")

    # Log the exception before dumping
    logging.error("Uncaught exception: %s", exception_value)
    logging.error(
        "Stack trace:\n%s",
        "".join(traceback.format_exception(exception_type, exception_value, tb)),
    )

    try:
        # Set up mini-dump creation using pywin32 (exception type, exception value, traceback)
        hProcess = win32api.GetCurrentProcess()
        exception_info = pywintypes.BSTR(str(exception_value))
        logging.info(f"Creating crash dump at {dump_file}")

        # Save the minidump
        win32process.CreateProcess(
            None, sys.argv[0], None, None, 0, 0, None, None, None, None
        )

        # Now use the Debugger or another appropriate API to capture crash dumps
        with open(dump_file, "w") as f:
            f.write(f"Crash dump saved on: {timestamp}\n")
            f.write(f"Exception: {exception_value}\n")
            f.write(f"Stack Trace:\n{traceback.format_exc()}")
    except Exception as e:
        logging.error(f"Failed to write crash dump: {e}")


def install_exception_handler():
    """Set up custom exception handler to catch unhandled exceptions."""
    sys.excepthook = write_minidump


def restart_application():
    """Restarts the application using subprocess for automated recovery."""
    try:
        logging.info("Restarting application...")
        subprocess.Popen([sys.executable] + sys.argv)
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


def watchdog(self):
    """Watchdog thread to monitor application health and attempt recovery if needed."""
    while True:
        time.sleep(10)  # Check every 10 seconds
        if not self.is_healthy():
            logging.warning("Application health check failed. Attempting recovery.")
            self.attempt_recovery()


def is_healthy(self):
    """Check application health by verifying core components are responsive."""
    # Add checks here, by ensuring key objects are not None or verifying thread responsiveness
    return self.afs_path is not None and self.tree.get_children()  # Simplified example


def attempt_recovery(self):
    """Attempt to recover the application by reloading resources or restarting components."""
    try:
        if self.afs_path:
            with open(self.afs_path, "rb") as afs_file:
                self.parse_afs(afs_file)  # Re-parse to attempt recovery
            messagebox.showinfo("Recovery", "Application recovered successfully.")
    except Exception as e:
        logging.error(f"Recovery attempt failed: {e}")
        messagebox.showerror(
            "Recovery Failed",
            "Automatic recovery was unsuccessful. Please restart the application.",
        )


def run_as_admin():
    """Attempt to re-launch the application with elevated privileges."""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        logging.info("Requesting admin privileges to continue.")
        try:
            # Relaunch the application with elevated privileges
            safe_args = [shlex.quote(arg) for arg in sys.argv]
            subprocess.run(["runas", "/user:Administrator", sys.executable] + safe_args)
            sys.exit(0)  # Exit the current instance after launching the new one
        except Exception as e:
            logging.error(f"Failed to run as admin: {e}")
            messagebox.showerror(
                "Admin Privileges Required",
                "Could not acquire administrator privileges.",
            )
    else:
        logging.info("Already running with admin privileges.")


class AFSUtility:
    def __init__(self, root):
        self.root = root
        self.root.title("AFS Utility")

        # Setup exception handler for uncaught exceptions
        install_exception_handler()

        # Configure logging
        log_dir = os.path.join(
            os.getenv("LOCALAPPDATA"), "wcg847", "AFS Utility", "logs"
        )
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

        # Setup search bar at the top
        self.setup_search_bar()

        # Initialise AFS data storage
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
            columns=("name", "pointer", "size", "Creation Date", "comments"),
            show="headings",
        )
        for col in ("name", "pointer", "size", "Creation Date", "comments"):
            if col == "Creation Date":
                self.tree.heading(
                    col, text=col, command=partial(self.sort_by_column, col)
                )
            else:
                self.tree.heading(
                    col,
                    text=col.capitalize(),
                    command=partial(self.sort_by_column, col),
                )

        self.tree.column("name", width=200)
        self.tree.column("pointer", width=100)
        self.tree.column("size", width=100)
        self.tree.column("Creation Date", width=150)
        self.tree.column("comments", width=200)

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

        # Binding right-click key
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Menu for file and tools options
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
        tools_menu.add_command(
            label="Mass Extract", command=self.mass_extract
        )  # Added mass extract option

    def run_in_thread(self, target, *args):
        thread = threading.Thread(target=target, args=args)
        thread.start()

    def register_file_association():
        """Register .afs file association on Windows."""
        if sys.platform != "win32":
            logging.warning("File association is only supported on Windows.")
            return

        # Check if the program is running with admin privileges
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError(
                    "Admin privileges required to modify file associations."
                )

            # Get the path to the executable
            executable_path = os.path.abspath(sys.executable)
            logging.info(f"Executable Path: {executable_path}")

            # Define registry paths and values
            reg_paths = [
                (r"Software\Classes\.afs", "", "AFSUtility.File"),
                (r"Software\Classes\AFSUtility.File", "", "AFS Utility File"),
                (
                    r"Software\Classes\AFSUtility.File\DefaultIcon",
                    "",
                    f"{executable_path},0",
                ),
                (
                    r"Software\Classes\AFSUtility.File\shell\open\command",
                    "",
                    f'"{executable_path}" "%1"',
                ),
            ]

            # Set registry keys for file association
            for path, name, value in reg_paths:
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                    logging.info(f"Set registry value: {path} -> {value}")

            logging.info("File association registered successfully.")

        except PermissionError:
            # Prompt to restart as admin
            response = messagebox.askyesno(
                "Admin Privileges Required",
                "Admin privileges are required to register file associations.\n"
                "Would you like to restart this program as an administrator?",
            )
            if response:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
        except PermissionError:
            logging.warning(
                "Permission denied. File association requires admin privileges."
            )
            messagebox.showwarning(
                "File Association",
                "Admin privileges required to register file associations.",
            )
        except Exception as e:
            logging.error(f"Failed to register file association: {e}")
            messagebox.showerror(
                "File Association Error", "Unable to complete file association setup."
            )
        else:
            logging.info("File association registered successfully.")

    def create_new_afs_archive(self):
        # Start the archive creation in a separate thread
        self.run_in_thread(self._create_new_afs_archive)

    def _create_new_afs_archive(self):
        """Creates a new AFS archive, including file metadata and footer in TOC without affecting file count."""
        folder_path = filedialog.askdirectory(
            title="Select Folder with Files for New AFS Archive"
        )
        if not folder_path:
            return

        output_file = filedialog.asksaveasfilename(
            title="Save New AFS Archive As",
            defaultextension=".afs",
            filetypes=[("AFS Files", "*.afs")],
        )
        if not output_file:
            return

        files = [
            f
            for f in os.listdir(folder_path)
            if os.path.isfile(os.path.join(folder_path, f))
        ]
        if not files:
            self.root.after(
                0,
                lambda: messagebox.showwarning(
                    "No Files Found", "The selected folder does not contain any files."
                ),
            )
            return

        toc_entries = []
        file_names = []
        file_data = []
        pointer = 0x800  # Start data section after 0x800 offset for the header

        # Collect file data and metadata
        for file_name in files:
            file_path = os.path.join(folder_path, file_name)
            with open(file_path, "rb") as f:
                data = f.read()
                size = len(data)
                toc_entries.append((pointer, size))
                file_data.append(data)
                file_names.append(file_name.ljust(32, "\x00"))
                pointer += (size + 0x7FF) & ~0x7FF  # Align to next 0x800 boundary

        # Now calculate the footer pointer based on the last file’s data
        footer_pointer = pointer
        footer_size = 0x20
        toc_entries.append(
            (footer_pointer, footer_size)
        )  # Append footer as "last listing" in TOC
        footer_entries = []
        for idx, (name, (file_pointer, file_size)) in enumerate(
            zip(file_names, toc_entries)
        ):
            # Capture metadata: filename, creation date, and repeated TOC entries
            creation_date = datetime.datetime.now()
            footer_entries.append(
                {
                    "name": name,
                    "pointer": file_pointer,
                    "size": file_size,
                    "creation_date": creation_date,
                }
            )

        try:
            with open(output_file, "wb") as afs_file:
                afs_file.write(b"AFS\x00")  # AFS magic bytes
                afs_file.write(
                    struct.pack("<I", len(files))
                )  # Actual file count, excludes footer

                # Write the TOC entries for each file, includes footer
                for toc_entry in toc_entries:
                    afs_file.write(struct.pack("<II", *toc_entry))

                # Pad TOC to reach 0x800 offset for the data section
                current_pos = afs_file.tell()
                if current_pos < 0x800:
                    afs_file.write(b"\x00" * (0x800 - current_pos))

                # Write each file's data, aligning each to 0x800 boundaries
                for data in file_data:
                    afs_file.write(data)
                    padding = (0x800 - (len(data) % 0x800)) % 0x800
                    afs_file.write(b"\x00" * padding)

                # Align footer block to 2048-byte boundary
                current_pos = afs_file.tell()
                padding_needed = (0x800 - (current_pos % 0x800)) % 0x800
                afs_file.write(b"\x00" * padding_needed)

                # Write footer block containing filenames, creation dates, pointers, and sizes
                for entry in footer_entries:
                    afs_file.write(
                        entry["name"].encode("latin1")
                    )  # File name padded to 32 bytes

                    # Write creation date
                    afs_file.write(struct.pack("<H", entry["creation_date"].year))
                    afs_file.write(struct.pack("<H", entry["creation_date"].month))
                    afs_file.write(struct.pack("<H", entry["creation_date"].day))
                    afs_file.write(struct.pack("<H", entry["creation_date"].hour))
                    afs_file.write(struct.pack("<H", entry["creation_date"].minute))
                    afs_file.write(struct.pack("<H", entry["creation_date"].second))

                    # Writes the Size
                    afs_file.write(struct.pack("<I", entry["size"]))

                # Align copyright footer to 2048-byte boundary
                current_pos = afs_file.tell()
                padding_needed = (0x800 - (current_pos % 0x800)) % 0x800
                afs_file.write(b"\x00" * padding_needed)

                # Write copyright footer
                copyright_footer = "© 2024 AFS Utility".ljust(32, "\x00")
                afs_file.write(copyright_footer.encode("latin1"))

                # Final padding to align the file after the copyright footer
                current_pos = afs_file.tell()
                padding_needed = (0x800 - (current_pos % 0x800)) % 0x800
                afs_file.write(b"\x00" * padding_needed)

            self.root.after(
                0,
                lambda: messagebox.showinfo(
                    "Success", "New AFS archive created successfully."
                ),
            )

        except Exception as e:
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

    def load_afs_file(self):
        """Load an AFS file with graceful degradation on error."""
        afs_path = filedialog.askopenfilename(
            title="Select File", filetypes=[("Sofdec Archive File System", "*.afs")]
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

    def parse_afs(self, afs_file):
        # Clear previous entries
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Verify and parse the AFS header
        header = afs_file.read(4)
        if header[:3] != b"AFS" or header[3] != 0x00:
            messagebox.showerror(
                "Invalid Format", "The file is not a valid Sofdec archive."
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

        self.file_names = []
        self.file_dates = []  # List to store parsed dates
        self.file_sizes = []  # List to store parsed file sizes

        for _ in range(self.file_count):
            # File name parsing
            name = afs_file.read(0x20).decode("latin1").strip("\x00")
            self.file_names.append(name)

            # Read the creation date (formatted as YYMMDDHHMMSS in 2 bytes each)
            year = struct.unpack("<H", afs_file.read(2))[0]
            month = struct.unpack("<H", afs_file.read(2))[0]
            day = struct.unpack("<H", afs_file.read(2))[0]
            hour = struct.unpack("<H", afs_file.read(2))[0]
            minute = struct.unpack("<H", afs_file.read(2))[0]
            second = struct.unpack("<H", afs_file.read(2))[0]

            file_date = datetime.datetime(year, month, day, hour, minute, second)
            self.file_dates.append(
                file_date.strftime("%Y-%m-%d %H:%M:%S")
            )  # Store formatted date

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
            return

        # Print the parsed file names for verification
        logging.info(f"Parsed file names: {self.file_names}")

        # Fill Treeview with parsed data if header matches expected 2 or 3-byte patterns
        for idx in range(self.file_count):
            pointer, size = self.toc_entries[idx]

            # Seek to the file's starting position and read the first 4 bytes (for checking 2 or 3 bytes)
            afs_file.seek(pointer)
            file_header = afs_file.read(4)

            # Define allowed headers for ADX and SFD files
            allowed_headers = {b"\x80\x00", b"\x00\x00"}

            # Check if the header is valid for ADX or SFD files
            if file_header[:2] not in allowed_headers:
                logging.error(
                    f"Skipping file {self.file_names[idx]} due to invalid header {file_header.hex()}"
                )
                continue  # Skip this file if it does not have the expected magic header

            name = self.file_names[idx]
            formatted_size = self.format_size(size)
            description = self.descriptions.get(name, "")
            # In parse_afs Treeview insertion loop
            self.tree.insert(
                "",
                "end",
                values=(
                    name,
                    f"0x{pointer:X}",
                    formatted_size,
                    self.file_dates[idx],
                    description,
                ),
            )

            # After populating the tree with data, store the initial data for search reference
            self.original_data = [
                (self.tree.item(item, "values")) for item in self.tree.get_children()
            ]

    def format_size(self, size):
        if size == 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
        size = Decimal(size)
        index = 0
        while size >= 1024 and index < len(units) - 1:
            size /= 1024
            index += 1
        return f"{size.quantize(Decimal('0.1'))} {units[index]}"

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
        if column == "#4" and item_id:
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
        """Sort treeview by the given column."""
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
        else:
            data.sort(reverse=not self.sort_ascending)

        for index, (_, item) in enumerate(data):
            self.tree.move(item, "", index)

        # Update headings to indicate sort order
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
                "", "end", values=(name, f"0x{pointer:X}", formatted_size, description)
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