# Zyph - Secure Your Dependencies

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Zyph is an open-source dependency scanner designed to help developers secure their projects by analyzing the contents of the `node_modules` folder for suspicious or malicious code patterns. Using advanced static analysis heuristics, Zyph flags potential security risks—ranging from dangerous dynamic code execution (e.g., `eval()` or `Function()` usage) to signs of code obfuscation.

## Features

- **Real-time Scanning:** Recursively scan the `node_modules` folder to analyze every JavaScript file.
- **Advanced Heuristics:** Uses a comprehensive set of heuristics to detect dangerous patterns, including context-aware analysis.
- **Customizable Rules:** The heuristics are maintained in a separate file (`heuristics.js`) to allow easy updates and customizations.
- **CLI Integration:** Run scans directly from your terminal using a simple command.
- **Clear Reporting:** Get detailed, file-by-file reports highlighting potential issues with severity levels.

## Installation

### Prerequisites

- [**Node.js**](https://nodejs.org/) (v12 or higher)
- [**npm**](https://www.npmjs.com/)

### Installing Locally

Clone the repository and install the dependencies:

```bash
git clone https://github.com/SouthernCode/zyph-scanner.git
cd zyph-scanner
npm install
```

### Testing Locally Without Publishing

To test your changes locally without pushing to npm:

#### 1. Using npm link

```bash
npm link
# In another project directory, link the package:
npm link zyph
# Now you can run:
zyph scan
```

#### 2. Direct Execution

Run the CLI script directly from the repository:

```bash
node bin/cli.js
```

#### 3. Local npm Install

```bash
npm install --save ../path/to/zyph-scanner
```

## Usage

Once installed or linked, you can run a scan by executing the following command in your project directory (which contains a `node_modules` folder):

```bash
zyph scan
```

You should see output similar to:

```
🚀 Running Zyph Security Scan...

🔍 Scanning node_modules/ for suspicious code...
🚨 Issues found in node_modules/some-package/file.js:
  [HIGH] EVAL_USAGE: Direct use of eval() can execute arbitrary code. Unsanitized input can lead to remote code execution.
  [MEDIUM] DYNAMIC_TIMEOUT_INTERVAL: Using setTimeout with string arguments may execute dynamically generated code.
...

✅ Scan complete.
```

## Project Structure

- **`bin/cli.js`**  
  Main entry point for the command-line interface. This file handles scanning logic, AST traversal, and reporting.

- **`heuristics.js`**  
  Contains an array of advanced heuristics for detecting malicious or suspicious code patterns. Each heuristic includes an ID, description, severity level, and custom detection logic.

- **`package.json`**  
  Defines the project metadata, dependencies, scripts, and executable commands.

## Contributing

We welcome contributions to help improve Zyph. If you'd like to contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a detailed description of your changes.

Please review our [CONTRIBUTING.md](CONTRIBUTING.md) guidelines before submitting your pull request.

## License

Zyph is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have suggestions for improvements, please open an issue on our [GitHub repository](https://github.com/SouthernCode/zyph-scanner/issues).

---

Stay secure and happy coding with Zyph!
