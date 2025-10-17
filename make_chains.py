#!/usr/bin/env python3
import collections
import re
import sys

def make_chains_fast(input_file_path):
    """
    Parses a graph from a file, finds all paths from start nodes to end nodes,
    and prints them. This implementation correctly handles cycles to avoid infinite loops.

    Args:
        input_file_path: The path to the file containing the graph data.
    """
    graph = collections.defaultdict(list)
    in_degree = collections.defaultdict(int)
    nodes = set()
    
    line_regex = re.compile(r'^\s*(.*?)\s*---(.*?)\s*-->\s*(.*?)\s*$')

    try:
        with open(input_file_path, 'r') as f:
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

    def find_paths_from(node, current_path, visited):
        current_path_str = f"{current_path[0]} ---{current_path[1]}--> {node}" if current_path else node
        visited.add(node)

        if node not in graph:
            print(current_path_str)
            return

        is_end_of_path = True
        for edge_type, neighbor in graph[node]:
            if neighbor not in visited:
                is_end_of_path = False
                find_paths_from(neighbor, (current_path_str, edge_type), set(visited))
        
        if is_end_of_path:
            print(current_path_str)

    # Start the search from each identified starting node
    for start_node in start_nodes:
        find_paths_from(start_node, None, set())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./process_chains.py <input_file>", file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    make_chains_fast(input_file)
