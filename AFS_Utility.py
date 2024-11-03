import struct
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from decimal import Decimal


class AFSUtility:
    def __init__(self, root):
        self.root = root
        self.root.title("AFS Utility")

        # Initialise AFS data storage
        self.toc_entries = []  # Stores pointers and sizes of files
        self.file_names = []  # Stores file names
        self.file_count = 0  # Number of files including footer
        self.afs_path = None  # Stores path of currently loaded AFS file

        # Treeview widget with scrollbar
        self.tree_frame = tk.Frame(root)
        self.tree_frame.pack(fill="both", expand=True)

        # Create a Treeview with vertical scrollbar, with "name" as the first column
        self.tree = ttk.Treeview(
            self.tree_frame, columns=("name", "pointer", "size"), show="headings"
        )
        self.tree.heading("name", text="File Name")
        self.tree.heading("pointer", text="File Pointer")
        self.tree.heading("size", text="File Size")

        self.tree.column("name", width=200)
        self.tree.column("pointer", width=100)
        self.tree.column("size", width=100)

        self.scrollbar = ttk.Scrollbar(
            self.tree_frame, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscroll=self.scrollbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

        # Right-click context menu
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

        # Binding right-click key
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Menu for file and tools options
        self.menu = tk.Menu(root)
        root.config(menu=self.menu)

        file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open", command=self.load_afs_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)

        tools_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Add File", command=self.add_file)

    def load_afs_file(self):
        afs_path = filedialog.askopenfilename(
            title="Select File", filetypes=[("Sofdec Archive File System", "*.afs")]
        )
        if afs_path:
            self.afs_path = afs_path  # Store the AFS path for later usage
            try:
                with open(self.afs_path, "rb") as afs_file:
                    self.parse_afs(afs_file)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load AFS file: {e}")

    def parse_afs(self, afs_file):

        for item in self.tree.get_children():
            self.tree.delete(item)

        # Verify and parse the AFS header
        header = afs_file.read(4)
        if header[:3] != b"AFS" or header[3] != 0x00:
            messagebox.showerror(
                "Invalid Format", "The file is not a valid Sofdec archive."
            )
            return

        # No. of files in AFS
        self.file_count = struct.unpack("<I", afs_file.read(4))[0]

        # Start of TOC
        self.toc_entries = []
        for _ in range(self.file_count):
            pointer = struct.unpack("<I", afs_file.read(4))[0]
            size = struct.unpack("<I", afs_file.read(4))[0]
            self.toc_entries.append((pointer, size))

        # Parse footer block with file names
        afs_file.seek(self.toc_entries[-1][0] + self.toc_entries[-1][1])
        self.file_names = []

        for _ in range(self.file_count):
            name = afs_file.read(0x20).decode("latin1").strip("\x00")
            afs_file.read(0x10)  # Skip unknown flags
            self.file_names.append(name)

        # Fill Treeview with parsed file data.
        for idx in range(self.file_count - 1):
            pointer, size = self.toc_entries[idx]
            name = self.file_names[idx]
            formatted_size = self.format_size(size)  # Format size for readability
            self.tree.insert("", "end", values=(name, f"0x{pointer:X}", formatted_size))

    def format_size(self, size):
        """
        Convert file size to a human-readable format in KB, MB, GB, TB, PB, EB.

        Parameters:
        size (int or float): The file size in bytes. Must be a non-negative number.

        Returns:
        str: A formatted string representing the size in the appropriate unit.

        Raises:
        ValueError: If size is a negative number.
        """
        if size == 0:
            return "0 B"

        # Define units for file sizes
        units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]  # Extendable for larger sizes
        size = Decimal(size)  # Use Decimal for more precision

        index = 0
        while size >= 1024 and index < len(units) - 1:
            size /= 1024
            index += 1

        # Return formatted size with one decimal place for better readability
        return f"{size.quantize(Decimal('0.1'))} {units[index]}"

    def show_context_menu(self, event):
        # Display the context menu at the right-clicked position
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def extract_selected_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected.")
            return

        file_index = self.tree.index(selected_item[0])
        pointer, size = self.toc_entries[file_index]
        file_name = self.file_names[file_index]  # Use parsed file name as output name

        save_path = filedialog.asksaveasfilename(
            title="Save Extracted File", initialfile=file_name, defaultextension=".adx"
        )
        if save_path:
            try:
                with open(save_path, "wb") as output_file, open(
                    self.afs_path, "rb"
                ) as afs_file:
                    afs_file.seek(pointer)
                    output_file.write(afs_file.read(size))
                messagebox.showinfo(
                    "Success", f"File '{file_name}' extracted successfully."
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to extract file: {e}")

    def inject_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected.")
            return

        file_path = filedialog.askopenfilename(title="Select File to Inject")
        if file_path:

            # Placeholder.
            messagebox.showinfo(
                "Not Implemented",
                "File injection is not fully implemented.",
            )

    def delete_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No file selected.")
            return

        file_index = self.tree.index(selected_item[0])

        # Placeholder.
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

                # Placeholder.
                messagebox.showinfo(
                    "Not Implemented",
                    "Add file functionality is not fully implemented.",
                )


if __name__ == "__main__":
    root = tk.Tk()
    app = AFSUtility(root)
    root.geometry("600x400")
    root.mainloop()
