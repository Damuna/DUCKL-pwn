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
- `--dc [DC_FQDN]`
  Domain Controller fully-qualified domain name (used to target analysis within your lab).
- `--ns [DC_IP]`
  IP address of the name server or target host (used for integration in lab).
- `--no-gather`
  Run the analysis/pwn path using previously gathered graph/artifacts; skip the collection phase.
- `-u [USER]`
  Username under which to perform collection actions (only used in authorized testing).
- `-p [PASSWORD]`
  Password override (for local lab/harness only). Avoid storing plaintext passwords in .env.
- `-H [HASH]`
  Optional credential hash to use for authentication in local testing harnesses.
- `-k`
  Toggle for specific collection/analysis behavior (tool-specific; consult developer notes).
- `--help or -h`
  Show usage/help text.
### Example usage
Tto automatically collect and ingest bloodound data
```sh
ducklpwn -u [USER] [-p PASSWORD] --dc [DC_FQDN] --ns [DC_IP] [-k]
```
If bloodhound data are already uploaded
```sh
ducklpwn --dc [DC_FQDN] --ns [DC_IP] --no-gather
```
