from typing import List
from sim.events import SimEvent, EventType
from sim.models import NodeState

# simulate a brute force attack scenario
def bruteforce_attack_scenario(engine) -> List[SimEvent]:

    events = []

    # get all nodes and choose a random target
    nodes = list(
        engine.network.nodes.values()
    )

    target = engine.rng.choice(nodes)

    print(
        f"[BRUTEFORCE] Targeting "
        f"{target.node_id} "
        f"at tick {engine.tick}"
    )

    # random number of login attempts
    attempts = engine.rng.randint(1, 4)

    print(
        f"[BRUTEFORCE] "
        f"{attempts} login attempts"
    )

    for _ in range(attempts):

        # log login attempt
        events.append(
            SimEvent(
                tick=engine.tick,
                event_type=EventType.LOGIN_ATTEMPT,
                source="attacker",
                target=target.node_id,
                severity=2,
                details={
                    "attack_type": "bruteforce"
                }
            )
        )

        print(
            f"[BRUTEFORCE] "
            f"Login attempt on "
            f"{target.node_id}"
        )

        # 60% chance of successful login
        if engine.rng.random() < 0.6:

            print(
                f"[BRUTEFORCE] "
                f"Login successful on "
                f"{target.node_id}"
            )

            # log successful login
            events.append(
                SimEvent(
                    tick=engine.tick,
                    event_type=EventType.LOGIN_SUCCESS,
                    source="attacker",
                    target=target.node_id,
                    severity=4,
                    details={
                        "attack_type": "bruteforce"
                    }
                )
            )

            # infect target if clean
            if target.state == NodeState.CLEAN:

                target.state = (
                    NodeState.INFECTED
                )

                target.active_attacks.add(
                    "bruteforce"
                )

                # store infection metadata
                target.meta["infected_by"] = (
                    "bruteforce"
                )

                target.meta["infected_at"] = (
                    engine.tick
                )

                print(
                    f"[BRUTEFORCE] "
                    f"{target.node_id} "
                    f"compromised"
                )

                # log infection
                events.append(
                    SimEvent(
                        tick=engine.tick,
                        event_type=(
                            EventType.INFECT_SUCCESS
                        ),
                        source="bruteforce",
                        target=target.node_id,
                        severity=4,
                        details={
                            "attack_type": (
                                "bruteforce"
                            )
                        }
                    )
                )

            # stop after compromise
            break

    return events