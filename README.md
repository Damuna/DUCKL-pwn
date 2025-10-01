# DUCKL-pwn
Exploiting DACLs like a quacking pro!
## Requirements
- [bhcli](https://github.com/exploide/bhcli)
- [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) — optional, used for certain automated actions
- [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) — optional, used for certain automated actions
## Configuration
Copy the example config file `.env.example` into `.env` and edit locally
```sh
cp .env.example .env
```
## Usage 
Flags (high-level descriptions):
- `-dc [DC_FQDN]`
  Domain Controller fully-qualified domain name.
- `--dc-ip [DC_IP]`
  IP address of the name server or target host.
- `--no-gather`
  Run the analysis/pwn path using previously gathered graph/artifacts; skip the collection phase.
- `-u [USER]`
  Username of the LDAP usare to perform collection actions.
- `-p [PASSWORD]`
  Password of the LDAP usare to perform collection actions.
- `-H [HASH]`
  Hash of the LDAP usare to perform collection actions.
- `-k`
  Kerberos Ticket path of the LDAP usare to perform collection actions..
- `--help or -h`
  Show usage/help text.
### Example usage
Tto automatically collect and ingest bloodound data
```sh
ducklpwn -u [USER] [-p PASSWORD] -dc [DC_FQDN] --dc-ip [DC_IP] [-k]
```
If bloodhound data are already uploaded
```sh
ducklpwn -dc [DC_FQDN] --dc-ip [DC_IP] --no-gather
```
