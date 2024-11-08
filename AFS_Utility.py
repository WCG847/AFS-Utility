﻿import struct
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import json
import os
from decimal import Decimal

class AFSUtility:
    def __init__(self, root):
        self.root = root
        self.root.title("AFS Utility")

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
            columns=("name", "pointer", "size", "comments"),
            show="headings",
        )
        for col in ("name", "pointer", "size", "comments"):
            self.tree.heading(col, text=col.capitalize(), command=lambda c=col: self.sort_by_column(c))

        self.tree.column("name", width=200)
        self.tree.column("pointer", width=100)
        self.tree.column("size", width=100)
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
        self.context_menu.add_command(label="Extract Selected File", command=self.extract_selected_file)
        self.context_menu.add_command(label="Inject into Selected File", command=self.inject_file)
        self.context_menu.add_command(label="Delete Selected File", command=self.delete_file)
        self.context_menu.add_command(label="Upload Description.json", command=self.upload_description_json)

        # Binding right-click key
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Menu for file and tools options
        self.menu = tk.Menu(root)
        root.config(menu=self.menu)

        file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open", command=self.load_afs_file)
        file_menu.add_command(label="Create New AFS Archive", command=self.create_new_afs_archive)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)

        tools_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Add File", command=self.add_file)
        tools_menu.add_command(label="Mass Extract", command=self.mass_extract)  # Added mass extract option

    def create_new_afs_archive(self):
        """Creates a new AFS archive from selected files in a directory."""
        folder_path = filedialog.askdirectory(title="Select Folder with Files for New AFS Archive")
        if not folder_path:
            return
        
        # Retrieve output file parameters from the user
        output_file = filedialog.asksaveasfilename(
            title="Save New AFS Archive As", defaultextension=".afs", filetypes=[("AFS Files", "*.afs")]
        )
        if not output_file:
            return
        
        # Collect files in the selected directory
        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
        
        if not files:
            messagebox.showwarning("No Files Found", "The selected folder does not contain any files.")
            return

        # Build the TOC and determine file sizes and pointers
        toc_entries = []
        file_names = []
        file_data = []
        pointer = 0x800  # Start data section after 0x800 offset for the header

        # Read each file and append to data buffer
        for file_name in files:
            file_path = os.path.join(folder_path, file_name)
            with open(file_path, "rb") as f:
                data = f.read()
                size = len(data)

                # Append TOC entry (pointer and size)
                toc_entries.append((pointer, size))
                file_data.append(data)

                # Append file name, ensuring it’s 32 bytes in length for the footer
                file_names.append(file_name.ljust(32, '\x00'))

                # Update pointer for the next file, aligning to 0x800
                pointer += (size + 0x7FF) & ~0x7FF  # Align to next 0x800 boundary

        # Write AFS archive to the specified output file
        try:
            with open(output_file, "wb") as afs_file:
                # Write AFS header
                afs_file.write(b"AFS\x00")  # AFS magic bytes
                afs_file.write(struct.pack("<I", len(files)))  # Number of files
                
                # Write TOC entries
                for toc_entry in toc_entries:
                    afs_file.write(struct.pack("<II", *toc_entry))
                
                # Pad TOC to reach 0x800 offset for the data section
                current_pos = afs_file.tell()
                if current_pos < 0x800:
                    afs_file.write(b'\x00' * (0x800 - current_pos))
                
                # Write each file's data, aligning each to 0x800 boundaries
                for data in file_data:
                    afs_file.write(data)
                    padding = (0x800 - (len(data) % 0x800)) % 0x800
                    afs_file.write(b'\x00' * padding)

                # Write footer with file names
                for name in file_names:
                    afs_file.write(name.encode("latin1"))
                    afs_file.write(b'\x00' * 0x10)  # 16-byte padding per file name entry
                
                # Add copyright footer (32 bytes)
                copyright_footer = "© 2024 AFS Utility".ljust(32, '\x00')
                afs_file.write(copyright_footer.encode("latin1"))

            messagebox.showinfo("Success", "New AFS archive created successfully.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create AFS archive: {e}")

    def mass_extract(self):
        """Extract all files in the AFS to a selected directory."""
        if not self.afs_path:
            messagebox.showwarning("Warning", "No AFS file loaded.")
            return

        directory = filedialog.askdirectory(title="Select Directory for Mass Extraction")
        if not directory:
            return

        try:
            with open(self.afs_path, "rb") as afs_file:
                for idx, (pointer, size) in enumerate(self.toc_entries):
                    file_name = self.file_names[idx]
                    afs_file.seek(pointer)
                    file_data = afs_file.read(size)
                    file_path = os.path.join(directory, file_name)

                    with open(file_path, "wb") as output_file:
                        output_file.write(file_data)

            messagebox.showinfo("Success", "All files extracted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract files: {e}")

    def load_afs_file(self):
        afs_path = filedialog.askopenfilename(
            title="Select File", filetypes=[("Sofdec Archive File System", "*.afs")]
        )
        if afs_path:
            self.afs_path = afs_path  # Store the AFS path for later usage
            try:
                # Attempt to load the descriptions from the JSON file
                self.load_description_json()

                with open(self.afs_path, "rb") as afs_file:
                    self.parse_afs(afs_file)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load AFS file: {e}")

    def load_description_json(self):
        """Load descriptions from description.json if it exists."""
        appdata_dir = os.getenv("LOCALAPPDATA") + "\\WCG847\\AFSTool"
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

        # Align to nearest 0x800 boundary if necessary
        if expected_footer_start % 0x800 != 0:
            aligned_footer_start = (expected_footer_start + 0x800) & ~0x7FF
            print(f"Non-aligned footer detected. Aligning to nearest 0x800 boundary.")
            print(f"Adjusted footer start: 0x{aligned_footer_start:X}")
            expected_footer_start = aligned_footer_start
        else:
            print(f"Footer is already aligned at: 0x{expected_footer_start:X}")

        afs_file.seek(expected_footer_start)

        # Print the final footer start location for debugging
        print(f"Final footer start: 0x{expected_footer_start:X}")

        # Attempt to parse footer block with file names
        self.file_names = []
        for _ in range(self.file_count):
            name = afs_file.read(0x20).decode("latin1").strip("\x00")
            afs_file.read(0x10)  # Skip unknown flags
            self.file_names.append(name)

        # Verify file names were parsed correctly
        if len(self.file_names) != self.file_count:
            messagebox.showerror(
                "Parsing Error",
                "The number of file names does not match the file count.",
            )
            return

        # Print the parsed file names for verification
        print("Parsed file names:", self.file_names)

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
                print(
                    f"Skipping file {self.file_names[idx]} due to invalid header {file_header.hex()}"
                )
                continue  # Skip this file if it does not have the expected magic header

            name = self.file_names[idx]
            formatted_size = self.format_size(size)
            description = self.descriptions.get(name, "")
            self.tree.insert(
                "", "end", values=(name, f"0x{pointer:X}", formatted_size, description)
            )

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
        appdata_dir = os.getenv("LOCALAPPDATA") + "\\WCG847\\AFSTool"
        os.makedirs(appdata_dir, exist_ok=True)
        description_path = os.path.join(appdata_dir, "description.json")
    
        # Creating a dictionary with the specified structure
        formatted_descriptions = {name: self.descriptions.get(name, "") for name in self.file_names}
    
        with open(description_path, "w") as json_file:
            json.dump(formatted_descriptions, json_file, indent=2)  # Use indent for pretty printing

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
                key=lambda t: int(t[0].replace("0x", ""), 16),
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
                appdata_dir = os.getenv("LOCALAPPDATA") + "\\WCG847\\AFSTool"
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


if __name__ == "__main__":
    root = tk.Tk()
    app = AFSUtility(root)
    root.geometry("700x400")
    root.mainloop()
