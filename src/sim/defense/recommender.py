from typing import List
from sim.events import SimEvent, EventType
from sim.models import NodeState

# Generate simple AI recommendations based on current network conditions
def recommendation_engine(engine) -> List[SimEvent]:

    events: List[SimEvent] = []

    # get infected and clean nodes
    infected = [n for n in engine.network.nodes.values() if n.state == NodeState.INFECTED]
    clean = [n for n in engine.network.nodes.values() if n.state == NodeState.CLEAN]

    # calculate average risk across all nodes
    avg_risk = sum(n.risk_score for n in engine.network.nodes.values()) / len(engine.network.nodes)

    # if many infected nodes, prioritize quarantine
    if len(infected) > len(engine.network.nodes) * 0.1:
        target = max(infected, key=lambda n: n.vuln_level) # select the most vulnerable infected one
        action = "quarantine"
        severity = 4

    # if the risk is high, prioritize patching
    elif avg_risk > 0.5 and clean:
        target = max(clean, key=lambda n: n.vuln_level) # select the most vulnerable clean node
        action = "patch"
        severity = 3

    else: # otherwise just monitor the system
        target = None
        action = "monitor"
        severity = 1

    # creating a recommendation event
    events.append(
        SimEvent(
            tick=engine.tick,
            event_type=EventType.RECOMMENDATION,
            target=target.node_id if target else "network",
            severity=severity,
            details={"action": action}
        )
    )

    return events