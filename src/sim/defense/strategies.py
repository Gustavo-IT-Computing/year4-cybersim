from typing import List
from sim.models import NodeState
from sim.events import SimEvent, EventType

# Isolate the most vulnerable infected nodes to stop spread
def quarantine_strategy(engine) -> List[SimEvent]:

    events = []

    # get all infected nodes
    infected_nodes = [
        n for n in engine.network.nodes.values()
        if n.state == NodeState.INFECTED
    ]

    # select top 3 most vulnerable infected nodes
    limit = max(1, int(len(infected_nodes) * 0.3))
    targets = sorted(infected_nodes, key=lambda n: n.vuln_level, reverse=True)[:limit]

    for node in targets:
        # change node state to quarantined
        node.state = NodeState.QUARANTINED
        node.active_attacks.clear()

        # log quarantine event
        events.append(
            SimEvent(
                tick=engine.tick,
                event_type=EventType.QUARANTINE,
                source="defender",
                target=node.node_id,
                severity=3
            )
        )

    return events

# Patch high-risk clean nodes to prevent future infections
def patch_vulnerable_nodes(engine) -> List[SimEvent]:

    events = []

    # select clean nodes with high vulnerability
    candidates = [
        n for n in engine.network.nodes.values()
        if n.state == NodeState.CLEAN and n.vuln_level > 0.6
    ]

    # select top 5 most vulnerable nodes
    targets = sorted(candidates, key=lambda n: n.vuln_level, reverse=True)[:5]

    for node in targets:
        # change node state to patched
        node.state = NodeState.PATCHED
        node.active_attacks.clear()

        # log patch event
        events.append(
            SimEvent(
                tick=engine.tick,
                event_type=EventType.PATCH,
                source="defender",
                target=node.node_id,
                severity=2
            )
        )

    return events