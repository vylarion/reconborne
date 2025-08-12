# Reconborne


**Reconborne** is an advanced, AI-driven reconnaissance tool designed for cybersecurity professionals. It leverages the power of the Gemini API to perform comprehensive reconnaissance tasks, including technology stack detection, SSL/TLS certificate analysis, subdomain enumeration, and vulnerability correlation. With a focus on usability, performance, and detailed reporting, Reconborne streamlines security assessments and penetration testing workflows.

## Table of Contents
- [Demo](#demo)
- [Features](#features)
- [Installation](#installation)
  - [Option 1: Docker](#option-1-docker)
  - [Option 2: Local Installation](#option-2-local-installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Dependencies](#dependencies)
- [Output](#output)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Demo

Below are screenshots showcasing Reconborne in action. These demonstrate the tool's user interface, scan progress, and sample output reports.

- **Video Demo**:


https://github.com/user-attachments/assets/817e3800-32b8-4f4b-aace-e4bf4e828a44


- **Initiation**: Starting a scan with the command-line interface.
  ![Scan Initiation](https://github.com/vylarion/reconborne/blob/05578e0657915721e56730b78eae6e6976248721/Assets/Demo1.png)
- **Progress Output**: Real-time progress tracking with the rich console interface.
  ![Progress Output](https://github.com/vylarion/reconborne/blob/05578e0657915721e56730b78eae6e6976248721/Assets/Demo%202.png)
- **Sample Report**: Example markdown report generated after a scan.
  ![Sample Report](https://github.com/vylarion/reconborne/blob/05578e0657915721e56730b78eae6e6976248721/Assets/Demo%203.png)

## Features
- **Technology Stack Detection**: Identifies CMS, frameworks, servers, programming languages, databases, and security tools using Wappalyzer, BuiltWith, and custom fingerprinting.
- **SSL/TLS Certificate Analysis**: Evaluates certificate details, security posture, vulnerabilities, and trust levels.
- **Subdomain Enumeration**: Discovers subdomains using DNS resolution techniques.
- **Port Scanning**: Performs enhanced Nmap scans to identify open ports, services, and operating systems.
- **Passive Network Analysis**: Conducts passive traffic analysis with tools like Tshark (optional).
- **Vulnerability Correlation**: Maps detected technologies and open ports to known vulnerabilities.
- **AI-Powered Reporting**: Generates detailed markdown reports using the Gemini API, with fallback reporting for non-AI environments.
- **Customizable Configuration**: Supports YAML-based configuration for timeouts, threads, and API keys.
- **Rich Console Interface**: Provides a modern, user-friendly interface with progress tracking and colored output.

## Installation

🚀 **Install & Use Reconborne – From Zero to Report**

Reconborne can be installed using one of two methods: Docker for a quick, containerized setup, or a local installation for full control over the environment.

### Option 1: Docker

This option allows you to run Reconborne without installing dependencies locally, using a pre-built Docker image.

1. **Ensure Docker is Installed**
   - Install Docker on your system: [Docker Installation Guide](https://docs.docker.com/get-docker/).

2. **Run Reconborne with Docker**
   ```bash
   docker run --rm -it \
     -e GEMINI_API_KEY=YOUR_REAL_KEY_HERE \
     ghcr.io/vylarion/reconborne:latest \
     example.com
   ```
   - Replace `YOUR_REAL_KEY_HERE` with your Gemini API key.
   - Optionally, add Shodan and VirusTotal API keys via environment variables:
     ```bash
     -e SHODAN_API_KEY=YOUR_SHODAN_KEY \
     -e VIRUSTOTAL_API_KEY=YOUR_VT_KEY
     ```

3. **View the Report**
   The report will be generated in the container and saved as `<target>-report.md`. To access it, mount a local directory:
   ```bash
   docker run --rm -it \
     -e GEMINI_API_KEY=YOUR_REAL_KEY_HERE \
     -v $(pwd)/reports:/app/reports \
     ghcr.io/vylarion/reconborne:latest \
     example.com -o /app/reports/report.md
   ```
   Then open the report:
   ```bash
   code reports/report.md   # VS Code
   # or
   open reports/report.md   # macOS
   ```

### Option 2: Local Installation

This option provides full control over the environment and is ideal for advanced users or those integrating Reconborne into existing workflows.

1. **Clone the Repository**
   ```bash
   git clone https://github.com/vylarion/reconborne.git
   cd reconborne
   ```

2. **Install System Dependencies**
   | OS                  | Command                                              |
   |---------------------|------------------------------------------------------|
   | Ubuntu / Debian / Kali | `sudo apt update && sudo apt install -y nmap tshark recon-ng` |
   | macOS (Homebrew)    | `brew install nmap wireshark-cli recon-ng`           |
   | Windows (choco)     | `choco install nmap wireshark-cli`                   |

3. **Install Python Packages**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

4. **Set Your API Key**
   Create a `.env` file in the project folder:
   ```bash
   echo "GEMINI_API_KEY=YOUR_REAL_KEY_HERE" > .env
   ```
   Optionally, add Shodan and VirusTotal API keys:
   ```bash
   echo "SHODAN_API_KEY=YOUR_SHODAN_KEY" >> .env
   echo "VIRUSTOTAL_API_KEY=YOUR_VT_KEY" >> .env
   ```

5. **Verify Installation**
   Run the tool with the help command to ensure it’s set up correctly:
   ```bash
   python3 reconborne.py --help
   ```

## Usage

Reconborne is a command-line tool with flexible options for scanning and reporting. Below are some example commands:

| Goal              | Command                                      |
|-------------------|----------------------------------------------|
| Quick scan        | `python3 reconborne.py example.com --quick`  |
| Deep scan         | `python3 reconborne.py example.com`          |
| Custom output     | `python3 reconborne.py 192.168.1.1 -o report.md` |

### Options
- `-o, --output <file>`: Specify output file for the report (default: `<target>-report.md`).
- `-t, --timeout <seconds>`: Set scan timeout.
- `--threads <number>`: Set number of concurrent threads.
- `--no-passive`: Skip passive network analysis.
- `-q, --quick`: Run in quick scan mode (faster but less thorough).
- `-v, --verbose`: Enable verbose output.
- `-h, --help`: Show help message.

### View the Report
After running a scan, open the generated markdown file:
```bash
code example.com-report.md   # VS Code
# or
open example.com-report.md   # macOS
```

## Configuration

Reconborne uses a `reconborne_config.yaml` file for customization. If not present, a default configuration is created automatically. Key configuration options include:

- **Timeouts**: HTTP requests, SSL connections, subprocesses, DNS lookups.
- **Scan Options**: Thread count, Nmap timing, passive scan settings.
- **API Keys**: Gemini, Shodan, and VirusTotal API keys.
- **Output Settings**: Enable/disable raw data saving, PDF generation, and screenshots.

Example `reconborne_config.yaml`:
```yaml
timeouts:
  http_request: 10
  ssl_connection: 10
  subprocess: 60
  dns_lookup: 5
scan_options:
  max_threads: 10
  nmap_timing: T4
  enable_passive_scan: true
  passive_duration: 30
api_keys:
  gemini_api_key: null
  shodan_api_key: null
  virustotal_api_key: null
output:
  save_raw_data: true
  generate_pdf: false
  include_screenshots: false
```

## Dependencies

Required Python packages (listed in `requirements.txt`):
- `click`
- `requests`
- `pyyaml`
- `rich`
- `pyfiglet`
- `colorama`
- `google-generativeai`
- `pandas`
- `dnspython` (optional, for subdomain enumeration)
- `builtwith` (optional, for tech stack detection)
- `Wappalyzer` (optional, for advanced tech stack detection)

System dependencies:
- `nmap`: For port scanning.
- `tshark` (or `wireshark-cli`): For passive network analysis.
- `recon-ng`: For enhanced reconnaissance capabilities.

## Output

Reconborne generates a detailed markdown report summarizing findings, including:
- Open ports and services.
- Detected technologies and JavaScript libraries.
- SSL/TLS certificate details and vulnerabilities.
- Subdomains and passive network analysis results.
- Correlated vulnerabilities with severity levels.

Reports are saved to the specified output file or `<target>-report.md` by default.

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please ensure your code follows PEP 8 and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

- **Author**: Vylarion
- **GitHub**: [vylarion](https://github.com/vylarion)
- **Issues**: Report bugs or suggest features via [GitHub Issues](https://github.com/vylarion/reconborne/issues)
