# NTLM Relay Gat

![gat](img/gat.png)

## Description

NTLM Relay Gat is a powerful tool designed to automate the exploitation of NTLM relays using `ntlmrelayx.py` from the Impacket tool suite. By leveraging the capabilities of `ntlmrelayx.py`, NTLM Relay Gat streamlines the process of exploiting NTLM relay vulnerabilities, offering a range of functionalities from listing SMB shares to executing commands on MSSQL databases.

## Features

- **Multi-threading Support**: Utilize multiple threads to perform actions concurrently.
- **SMB Shares Enumeration**: List available SMB shares.
- **SMB Shell Execution**: Execute a shell via SMB.
- **Secrets Dumping**: Dump secrets from the target.
- **MSSQL Database Enumeration**: List available MSSQL databases.
- **MSSQL Command Execution**: Execute operating system commands via xp_cmdshell or start SQL Server Agent jobs.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- `proxychains` properly configured with ntlmrelayx SOCKS relay port
- Python 3.6+

## Installation

To install NTLM Relay Gat, follow these steps:

1. Ensure that Python 3.6 or higher is installed on your system.

2. Clone NTLM Relay Gat repository:

```bash
git clone https://github.com/ad0nis/ntlm_relay_gat.git
cd ntlm_relay_gat
```

3. Install dependencies, if you don't have them installed already:

```bash
pip install -r requirements.txt
```

NTLM Relay Gat is now installed and ready to use.

## Usage

To use NTLM Relay Gat, execute the script with the desired options. Here are some examples of how to run NTLM Relay Gat:

```bash
# List available SMB shares using 10 threads
python ntlm_relay_gat.py --smb-shares -t 10

# Execute a shell via SMB
python ntlm_relay_gat.py --smb-shell --shell-path /path/to/shell

# Dump secrets from the target
python ntlm_relay_gat.py --dump-secrets

# List available MSSQL databases
python ntlm_relay_gat.py --mssql-dbs

# Execute an operating system command via xp_cmdshell
python ntlm_relay_gat.py --mssql-exec --mssql-method 1 --mssql-command 'whoami'
```

## Disclaimer

NTLM Relay Gat is intended for educational and ethical penetration testing purposes only. Usage of NTLM Relay Gat for attacking targets without prior mutual consent is illegal. The developers of NTLM Relay Gat assume no liability and are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
