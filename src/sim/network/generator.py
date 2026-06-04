import random
from sim.models import Node, NodeState, DeviceType, NetworkZone

# generate a random network of nodes and connections
def generate_network(size=50):

    nodes = {}  # store all nodes
    edges = {}  # store connections between nodes

    # create nodes
    for i in range(size):

        node_id = f"N{i}"  # unique node ID

        # assign device types using weighted probabilities
        device_type = random.choices(
            [DeviceType.WORKSTATION, DeviceType.SERVER, DeviceType.DATABASE, DeviceType.IOT],
            weights=[0.55, 0.20, 0.10, 0.15]
        )[0]

        # assign network zone and vulnerability based on device type
        if device_type == DeviceType.SERVER:
            zone = NetworkZone.DMZ
            vuln = random.uniform(0.2, 0.5)

        elif device_type == DeviceType.DATABASE:
            zone = NetworkZone.INTERNAL
            vuln = random.uniform(0.1, 0.4)

        elif device_type == DeviceType.IOT:
            zone = NetworkZone.IOT
            vuln = random.uniform(0.6, 0.9)

        else:
            zone = NetworkZone.INTERNAL
            vuln = random.uniform(0.4, 0.7)

        # create node object
        nodes[node_id] = Node(
            node_id=node_id,
            vuln_level=vuln,
            zone=zone,
            device_type=device_type
        )

    # create random connections between nodes
    for node_id in nodes:

        # randomly select 2–5 connections
        num_connections = min(len(nodes) - 1, random.randint(2, 5))
        connections = random.sample(list(nodes.keys()), num_connections)

        # remove self-connections
        edges[node_id] = list(set(connections) - {node_id})

    # ensure connections are symmetric
    for node, neighbors in edges.items():
        for n in neighbors:
            edges.setdefault(n, [])
            if node not in edges[n]:
                edges[n].append(node)

    # infect one random node at the start
    initial = random.choice(list(nodes.values()))
    initial.state = NodeState.INFECTED

    return nodes, edges