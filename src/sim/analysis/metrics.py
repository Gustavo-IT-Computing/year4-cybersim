from sim.models import NodeState

# function to calculate the risk based on compromised nodes
def calculate_risk(engine):

    total_nodes = len(engine.network.nodes)

    infected_nodes = [
        n
        for n in engine.network.nodes.values()
        if n.state == NodeState.INFECTED
    ]

    quarantined_nodes = [
        n
        for n in engine.network.nodes.values()
        if n.state == NodeState.QUARANTINED
    ]

    infected_count = len(infected_nodes)
    quarantined_count = len(quarantined_nodes)

    # base infection pressure
    infection_ratio = infected_count / total_nodes
    risk = infection_ratio * 70

    # impact of critical systems
    critical_bonus = 0

    for node in infected_nodes:

        if node.device_type.value == "server":
            critical_bonus += 2

        elif node.device_type.value == "database":
            critical_bonus += 3

    critical_bonus = min(20, critical_bonus)

    risk += critical_bonus

    # exposure based on infected node connections
    if infected_count > 0:

        avg_connections = sum(
            len(engine.network.neighbors(n.node_id))
            for n in infected_nodes
        ) / infected_count

        normalized_exposure = avg_connections / total_nodes

        risk += normalized_exposure * 15

    # quarantined nodes still contribute to risk
    quarantine_ratio = quarantined_count / total_nodes
    risk += quarantine_ratio * 20

    # if infection is gone, risk depends only on quarantine impact
    if infected_count == 0:
        risk = quarantine_ratio * 30

    return round(min(100, risk), 2)

# collect basic network statistics for current tick
def collect_metrics(engine):

    total_nodes = len(engine.network.nodes)

    infected = sum(
        1
        for n in engine.network.nodes.values()
        if n.state == NodeState.INFECTED
    )

    quarantined = sum(
        1
        for n in engine.network.nodes.values()
        if n.state == NodeState.QUARANTINED
    )

    patched = sum(
        1
        for n in engine.network.nodes.values()
        if n.state == NodeState.PATCHED
    )

    clean = sum(
        1
        for n in engine.network.nodes.values()
        if n.state == NodeState.CLEAN
    )

    risk = calculate_risk(engine)

    return {
        "tick": engine.tick,
        "total_nodes": total_nodes,
        "infected": infected,
        "quarantined": quarantined,
        "patched": patched,
        "clean": clean,
        "risk": risk
    }

# record state of each node for dashboard/history
def snapshot_state(engine):

    snapshot = {}

    for node_id, node in engine.network.nodes.items():
        snapshot[node_id] = node.state.value

    return snapshot