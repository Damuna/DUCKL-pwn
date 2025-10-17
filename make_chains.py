#!/usr/bin/env python3
import collections
import re
import sys


def make_chains_fast(input_file_path, dacl_output_file, member_output_file):
    """
    Parses a graph from a file, finds all paths from start nodes to end nodes,
    and outputs them to two separate files: DACL chains and membership chains.
    """
    graph = collections.defaultdict(list)
    in_degree = collections.defaultdict(int)
    nodes = set()

    line_regex = re.compile(r"^\s*(.*?)\s*---(.*?)\s*-->\s*(.*?)\s*$")

    try:
        with open(input_file_path, "r") as f:
            for line in f:
                match = line_regex.match(line)
                if not match:
                    continue

                source, edge_type, target = match.groups()

                graph[source].append((edge_type, target))
                nodes.add(source)
                nodes.add(target)
                in_degree[target] += 1
    except FileNotFoundError:
        print(f"Error: File not found at '{input_file_path}'", file=sys.stderr)
        sys.exit(1)

    start_nodes = [node for node in nodes if in_degree[node] == 0]

    dacl_chains = set()
    member_chains = set()

    def find_paths_from(node, current_path, visited, current_edges):
        visited.add(node)

        # Build the current chain string
        if current_path:
            current_chain = f"{current_path} ---{current_edges[-1][0]}--> {node}"
        else:
            current_chain = node

        # Check if this is an end node (no outgoing edges)
        if node not in graph:
            process_complete_chain(current_chain, current_edges)
            return

        # Continue traversal
        has_unvisited = False
        for edge_type, neighbor in graph[node]:
            if neighbor not in visited:
                has_unvisited = True
                new_edges = current_edges + [(edge_type, neighbor)]
                find_paths_from(neighbor, current_chain, visited.copy(), new_edges)

        # If no unvisited neighbors, this path ends here
        if not has_unvisited:
            process_complete_chain(current_chain, current_edges)

    def process_complete_chain(full_chain, edges):
        # --- IMPROVED: Extract pure membership chains ---
        start_node = full_chain.split(" ")[0]
        path_nodes = [start_node] + [edge[1] for edge in edges]

        for i, (edge_type, target) in enumerate(edges):
            if "MemberOf" in edge_type:
                source = path_nodes[i]
                member_chain = f"{source} ---{edge_type}--> {target}"
                member_chains.add(member_chain)

        # Create DACL chain by removing MemberOf edges and their groups
        dacl_chain_parts = []
        current_source = full_chain.split(" ")[0]

        i = 0
        while i < len(edges):
            edge_type, target = edges[i]

            if "MemberOf" in edge_type:
                # Skip this MemberOf edge and look for the next non-MemberOf edge
                i += 1
                # Find the next non-MemberOf edge from the target (group)
                while i < len(edges) and "MemberOf" in edges[i][0]:
                    i += 1
                if i < len(edges):
                    # Connect current source directly to the target of non-MemberOf edge
                    next_edge_type, next_target = edges[i]
                    dacl_chain_parts.append(
                        f"{current_source} ---{next_edge_type}--> {next_target}"
                    )
                    current_source = next_target
                    i += 1
            else:
                # Regular edge, add to DACL chain
                dacl_chain_parts.append(f"{current_source} ---{edge_type}--> {target}")
                current_source = target
                i += 1

        # Join the DACL chain parts
        if dacl_chain_parts:
            # Connect consecutive parts properly
            final_dacl_chain = dacl_chain_parts[0]
            for part in dacl_chain_parts[1:]:
                last_node = final_dacl_chain.split("--> ")[-1].strip()
                new_part_source = part.split(" ")[0].strip()

                if last_node != new_part_source:
                    final_dacl_chain += f" ---{part.split('---')[1].split('-->')[0]}--> {part.split('--> ')[-1]}"
                else:
                    # --- THIS IS THE FIX ---
                    # Instead of replacing the chain, append the new segment.
                    # e.g., part is "B ---perm--> C", we append " ---perm--> C"
                    edge_and_target = part.split(" ", 1)[1]
                    final_dacl_chain += f" {edge_and_target}"

            dacl_chains.add(final_dacl_chain)

    # Start the search from each identified starting node
    for start_node in start_nodes:
        find_paths_from(start_node, "", set(), [])

    # Write DACL chains to file
    try:
        with open(dacl_output_file, "w") as f:
            for chain in sorted(dacl_chains):
                f.write(chain + "\n")
    except IOError as e:
        print(f"Error writing to DACL output file: {e}", file=sys.stderr)
        sys.exit(1)

    # Write membership chains to file
    try:
        with open(member_output_file, "w") as f:
            for chain in sorted(member_chains):
                f.write(chain + "\n")
    except IOError as e:
        print(f"Error writing to member output file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    input_file = sys.argv[1]
    dacl_output = sys.argv[2]
    member_output = sys.argv[3]
    make_chains_fast(input_file, dacl_output, member_output)
