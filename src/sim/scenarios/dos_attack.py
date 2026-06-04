from typing import List
from sim.events import SimEvent, EventType
from sim.models import NodeState

# simulate a denial-of-service attack
def dos_attack_scenario(engine) -> List[SimEvent]:

    events = []

    # select random target node
    nodes = list(
        engine.network.nodes.values()
    )

    target = engine.rng.choice(nodes)

    print(
        f"[DOS] Targeting {target.node_id} "
        f"at tick {engine.tick}"
    )

    target.active_attacks.add("dos")

    # generate attack traffic intensity
    traffic = engine.rng.randint(
        50,
        200
    )

    print(
        f"[DOS] Traffic level: {traffic}"
    )

    # log DoS attack event
    events.append(
        SimEvent(
            tick=engine.tick,
            event_type=EventType.DOS_ATTACK,
            source="botnet",
            target=target.node_id,
            severity=5,
            details={
                "attack_type": "dos"
            }
        )
    )

    # increase risk due to traffic
    target.risk_score = min(
        1.0,
        target.risk_score + 0.3
    )

    # heavy traffic may bring service down
    if traffic > 150:

        print(
            f"[DOS] Service down on "
            f"{target.node_id}"
        )

        events.append(
            SimEvent(
                tick=engine.tick,
                event_type=(
                    EventType.SERVICE_DOWN
                ),
                source="botnet",
                target=target.node_id,
                severity=5,
                details={
                    "attack_type": "dos"
                }
            )
        )

        # vulnerable clean node may fail
        if (
            target.state == NodeState.CLEAN
            and target.risk_score > 0.7
        ):

            target.state = (
                NodeState.INFECTED
            )

            print(
                f"[DOS] {target.node_id} "
                f"became infected"
            )

            # log infection
            events.append(
                SimEvent(
                    tick=engine.tick,
                    event_type=(
                        EventType.INFECT_SUCCESS
                    ),
                    source="dos",
                    target=target.node_id,
                    severity=4,
                    details={
                        "attack_type": "dos"
                    }
                )
            )

    return events