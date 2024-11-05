# AFS Utility

Welcome to the AFS Utility, a powerful and user-friendly tool designed for managing AFS (Archive File System) files, originally defined by CRI Middleware Co., Ltd. in 2000. This application provides an intuitive interface for creating, extracting, and managing AFS archives, making it an essential tool for developers, modders, and anyone working with AFS files.

## Table of Contents

- [Key Features](#key-features)
- [Benefits](#benefits)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Licence](#licence)

## Key Features

- **Intuitive GUI**: Built using Tkinter, the AFS Utility features an easy-to-navigate graphical interface that simplifies the AFS file handling process.

- **Comprehensive File Management**:
  - **Create New AFS Archives**: Easily compile multiple files into a single AFS archive with a user-friendly file selection process.
  - **Extract Files**: Selectively extract individual files or perform mass extraction to a chosen directory, facilitating quick access to archive contents.

- **Dynamic File Description Management**: Load and manage file descriptions via a JSON file, allowing users to provide additional context for each file in their archives.

- **Robust Sorting and Filtering**: Sort files within the archive based on name, pointer, size, and comments, enhancing the user's ability to navigate large archives effortlessly.

- **Contextual Operations**: Right-click context menus offer quick access to essential operations such as file extraction, deletion, and description management.

- **Extensible**: Support for future features such as file injection and deletion provides a foundation for ongoing development and enhancements.

## Benefits

- **Time-Saving**: The AFS Utility reduces the complexity and time involved in handling AFS files, enabling users to focus on their core projects instead of manual file management.

- **Enhanced Productivity**: With features like mass extraction and dynamic descriptions, users can streamline their workflows and maintain better organisation within their projects.

- **User-Centric Design**: The focus on a clean and intuitive interface ensures that users can easily navigate the application, regardless of their technical background.

- **Community Driven**: This tool welcomes contributions and suggestions, fostering a collaborative environment for continuous improvement.

## Installation

1. **Clone the Repository**:
```bash
git clone https://github.com/WCG847/AFS-Utility.git
cd afs-utility
```

2. **Run the Application**:
Ensure you have Python 3x installed, and start the AFS Utility:
```bash
python afs_utility.py
```

Alternatively, get the latest compiled file from here. [Download](https://github.com/WCG847/AFS-Utility/releases/latest)


## Usage

- To create a new AFS archive, select **File > Create New AFS Archive**, choose the directory with your files, and specify the output file.
- To extract files, load your AFS file with **File > Open**, then right-click to extract individual files or use **Tools > Mass Extract**.
- To manage file descriptions, upload a `description.json` file that contains the relevant descriptions in the specified format.

## Contributing

Contributions are welcome! If you'd like to contribute to the AFS Utility, please fork the repository and submit a pull request. Make sure to update the documentation as needed.

## Licence

This project is licenced under the GPL 3.0 Licence - see the [LICENSE](LICENSE) file for details.

---

### Acknowledgements

Special thanks to **CRI Middleware Co., Ltd.** for the original AFS format released in 2000, which has paved the way for this utility and many creative projects worldwide.

---

For more information, visit our [GitHub Page](https://github.com/WCG847/AFS-Utility).
