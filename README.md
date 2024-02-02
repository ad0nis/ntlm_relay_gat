# Impacket Relay Gat

![gat](img/gat.png)

## Description

Relay Gat is a powerful tool designed to automate the exploitation of NTLM relays using `ntlmrelayx.py` from the Impacket suite. By leveraging the capabilities of `ntlmrelayx.py`, Relay Gat streamlines the process of exploiting NTLM relay vulnerabilities, offering a range of functionalities from listing SMB shares to executing commands on MSSQL databases.

## Features

- **Multi-threading Support**: Utilize multiple threads to perform actions concurrently.
- **SMB Shares Enumeration**: List available SMB shares.
- **SMB Shell Execution**: Execute a shell via SMB.
- **Secrets Dumping**: Dump secrets from the target.
- **MSSQL Database Enumeration**: List available MSSQL databases.
- **MSSQL Command Execution**: Execute operating system commands via xp_cmdshell or start SQL Server Agent jobs.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- `proxychains` properly configured with Impacket SOCKS relay port
- Python 3.6+
- Impacket
- Concurrent Futures Module (included in Python 3.2+)
- Requests Module

## Installation

To install Relay Gat, follow these steps:

1. Ensure that Python 3.6 or higher is installed on your system.

2. Install Impacket, which is a dependency for Relay Gat. You can obtain it from [Impacket's GitHub repository](https://github.com/fortra/impacket) or install it using pip:

```bash
pip install impacket
```

The other dependencies should already be present in your Python installation. If not, install them using pip:

```bash
pip install requests
```

Clone the Relay Gat repository:

```bash
git clone https://github.com/ad0nis/impacket_relay_gat.git
cd impacket_relay_gat
```

Relay Gat is now installed and ready to use.

## Usage

To use Relay Gat, execute the script with the desired options. Here are some examples of how to run Relay Gat:

```bash
# List available SMB shares using 10 threads
python relay-gat.py --smb-shares -t 10

# Execute a shell via SMB
python relay-gat.py --smb-shell --shell-path /path/to/shell

# Dump secrets from the target
python relay-gat.py --dump-secrets

# List available MSSQL databases
python relay-gat.py --mssql-dbs

# Execute an operating system command via xp_cmdshell
python relay-gat.py --mssql-exec --mssql-method 1 --mssql-command 'whoami'
```

## Disclaimer

Relay Gat is intended for educational and ethical penetration testing purposes only. Usage of Relay Gat for attacking targets without prior mutual consent is illegal. The developers of Relay Gat assume no liability and are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details.