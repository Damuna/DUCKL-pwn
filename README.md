# DUCKL-pwn
```sh
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
  Build attack chains for all possible users in the domain (NOT recommended for large domains.)
- `--owned {<FILE>}`       
  Build attack chains for users that are marked as owned in Bloodhound. If a file is specified, account are automatically marked as owned (Specify UPN for users and FQDN for PCs)
- `--help or -h`
  Show usage/help text.
### Example usage
#### With data collection
  Collect and ingest BloodHound data then run analysis for all users (NOT recommended for large domains.)
  ```sh
  ./ducklpwn.sh -u alice -p 's3cr3t' -dc corp.local --dc-ip 10.0.0.5 --all
  ```
  Collect and run analysis for specific owned users and mark them as owned
  ```sh
  ./ducklpwn.sh -u alice -p 's3cr3t' -dc corp.local --dc-ip 10.0.0.5 --owned owned.txt
  ```
  Collect and run analysis for users _previously_ marked as owned (manually mark them)
  ```sh
  ./ducklpwn.sh -u alice -p 's3cr3t' -dc corp.local --dc-ip 10.0.0.5 --owned
  ```
#### Without data collection
  Run analysis using previously gathered data for all users
  ```sh
  ./ducklpwn.sh -dc corp.local --dc-ip 10.0.0.5 --no-gather --all
  ```
  Run analysis using previously gathered data for specific owned users and mark them as owned
  ```sh
  ./ducklpwn.sh -dc corp.local --dc-ip 10.0.0.5 --no-gather --owned owned.txt
  ```
  Run analysis for users _previously_ marked as owned (manually mark them)
  ```sh
  ./ducklpwn.sh -dc corp.local --dc-ip 10.0.0.5 --no-gather --owned
  ```

