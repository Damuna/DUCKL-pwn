# DUCKL-pwn
```
===============================================================
   ____  _     ____  _  __ _           ____  _      _     
  /  _ \/ \ /\/   _\/ |/ // \         /  __\/ \  /|/ \  /|
  | | \|| | |||  /  |   / | |   _____ |  \/|| |  ||| |\ ||
  | |_/|| \_/||  \__|   \ | |_/\\____\|  __/| |/\||| | \||
  \____/\____/\____/\_|\_\\____/      \_/   \_/  \|\_/  \|
                                                        
  > Exploiting DACLs like a quacking pro!

      _          _          _          _          _
    >(')____,  >(')____,  >(')____,  >(')____,  >(') ___,
      (` =~~/    (` =~~/    (` =~~/    (` =~~/    (` =~~/
jgs~^~^`---'~^~^~^`---'~^~^~^`---'~^~^~^`---'~^~^~^`---'~^~^~

===============================================================
```
## Requirements
- Bloodhound community Edition
- [bhcli](https://github.com/exploide/bhcli)
- [bloodhound-cli](https://github.com/SpecterOps/bloodhound-cli)
- [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) — optional, used for certain automated actions
- [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) — optional, used for certain automated actions

## Configuration
Copy the example config file `.env.example` into `.env` and edit locally
```sh
chmod +x ducklpwn.sh; cp .env.example .env; nano .env
```
## Usage 
Flags:
- `-dc [DC_FQDN]`
  Domain Controller fully-qualified domain name.
- `--dc-ip [DC_IP]`
  IP address of the name server or target host.
- `--no-gather`
  Run the analysis/pwn path using previously gathered graph/artifacts; skip the collection phase.
- `-u [USER]`
  Username of the LDAP to perform Bloodhound collection.
- `-p [PASSWORD]`
  Password of the LDAP to perform Bloodhound collection.
- `-H [HASH]`
  Hash of the LDAP to perform Bloodhound collection.
- `-k`
  Kerberos Ticket path of the LDAP to perform Bloodhound collection.
- `--all`                
  Build attack chains for all possible users in the domain
- `--owned <FILE>`       
  Build attack chains for owned users listed in the specified file (Specify UPN for users and FQDN for PCs)
- `--help or -h`
  Show usage/help text.
### Example usage
To automatically collect and ingest Bloodhound data
```sh
./ducklpwn.sh -u [USER] [-p PASSWORD] -dc [DC_FQDN] --dc-ip [DC_IP] 
```
If Bloodhound data are already uploaded
```sh
./ducklpwn.sh -dc [DC_FQDN] --dc-ip [DC_IP] --no-gather
```
