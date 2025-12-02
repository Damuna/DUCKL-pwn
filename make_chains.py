#!/usr/bin/env python3
import collections
import re
import sys

def make_chains_clean(input_file_path, dacl_output_file, member_output_file):
    """
    Parses a graph from a file.
    1. Outputs all direct membership relationships to member_output_file.
    2. Calculates effective permissions.
       - If a node is a Group (has members), it applies the permission to the members 
         and SKIPS the group itself to avoid redundancy.
       - If a node is a User (has no members), it keeps the permission.
    """
    
    # Store edges
    member_edges = []
    permission_edges = []
    
    # Reverse membership: Group -> [List of immediate members]
    reverse_membership = collections.defaultdict(list)

    line_regex = re.compile(r"^\s*(.*?)\s*---(.*?)\s*-->\s*(.*?)\s*$")

    try:
        with open(input_file_path, "r") as f:
            for line in f:
                match = line_regex.match(line)
                if not match:
                    continue

                source, edge_type, target = match.groups()
                source = source.strip()
                edge_type = edge_type.strip()
                target = target.strip()

                if "MemberOf" in edge_type:
                    member_edges.append((source, target))
                    reverse_membership[target].append(source)
                else:
                    permission_edges.append((source, edge_type, target))

    except FileNotFoundError:
        print(f"Error: File not found at '{input_file_path}'", file=sys.stderr)
        sys.exit(1)

    # --- 1. Write Membership Chains ---
    try:
        with open(member_output_file, "w") as f:
            # Sort and unique
            unique_members = sorted(list(set(f"{s} ---MemberOf--> {t}" for s, t in member_edges)))
            for line in unique_members:
                f.write(line + "\n")
    except IOError as e:
        print(f"Error writing to member output file: {e}", file=sys.stderr)
        sys.exit(1)

    # --- 2. Calculate Effective Members (Group Expansion) ---
    
    # Iterative BFS to find all effective members (leaves and sub-groups) for a specific group
    def get_expanded_subjects(start_node):
        visited = set()
        queue = collections.deque([start_node])
        expanded = set()

        while queue:
            current = queue.popleft()
            # Who is a member of 'current'?
            direct_children = reverse_membership.get(current, [])
            
            for child in direct_children:
                if child not in visited:
                    visited.add(child)
                    expanded.add(child)
                    queue.append(child)
        return expanded

    # --- 3. Build and Write DACL Chains ---
    dacl_output_lines = set()

    for source, edge_type, target in permission_edges:
        # Get everyone who is effectively a member of 'source'
        sub_members = get_expanded_subjects(source)
        
        if sub_members:
            # CASE A: The Source is a Group (it has members).
            # We ONLY add the lines for the members (the users).
            # We SKIP the line for the 'source' (the group) to avoid redundancy.
            for member in sub_members:
                # Optional: Check if 'member' is itself a group? 
                # Usually, we want the ultimate users. 
                # If you want ONLY leaves (users) and no intermediate groups, 
                # we can check if 'member' is in reverse_membership.
                # For now, we assume if it's in the list, it's a valid attacker.
                dacl_output_lines.add(f"{member} ---{edge_type}--> {target}")
        else:
            # CASE B: The Source is a User (or empty group).
            # It has no members, so it is the direct attacker.
            dacl_output_lines.add(f"{source} ---{edge_type}--> {target}")

    try:
        with open(dacl_output_file, "w") as f:
            for line in sorted(dacl_output_lines):
                f.write(line + "\n")
    except IOError as e:
        print(f"Error writing to DACL output file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: ./script.py <input_file> <dacl_output> <member_output>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    dacl_output = sys.argv[2]
    member_output = sys.argv[3]
    make_chains_clean(input_file, dacl_output, member_output)