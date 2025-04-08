import networkx as nx
from pyvis.network import Network
from typing import List, Dict
import tempfile
import os

def build_threat_graph(iocs: Dict[str, List[Dict[str, str]]]) -> nx.Graph:
    """
    Build a threat graph from parsed IOC data.
    Each source becomes a hub with connections to its IOCs.
    """
    G = nx.Graph()

    for feed_name, entries in iocs.items():
        G.add_node(feed_name, label=feed_name, color="#ff9900", shape="box")

        for entry in entries:
            label = entry.get("value")
            if not label:
                continue
            node_id = f"{feed_name}:{label}"
            G.add_node(node_id, label=label, color="#0077cc")
            G.add_edge(feed_name, node_id)

    return G

def render_graph(graph: nx.Graph) -> str:
    """
    Render the NetworkX graph as an interactive HTML file using pyvis.
    Returns the path to the rendered file.
    """
    net = Network(height="600px", width="100%", bgcolor="#ffffff", font_color="black")

    # Load the NetworkX graph into PyVis
    net.from_nx(graph)

    # Apply visual styling
    net.toggle_physics(True)
    net.show_buttons(filter_=['physics'])

    # Save to a temporary file
    temp_path = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
    net.show(temp_path.name)

    return temp_path.name

def cleanup_graph_file(file_path: str):
    """Delete a previously generated graph file"""
    if os.path.exists(file_path):
        os.remove(file_path)
