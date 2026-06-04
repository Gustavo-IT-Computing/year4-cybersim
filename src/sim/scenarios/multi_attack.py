from typing import List
from sim.events import SimEvent
from sim.scenarios.malware_spread import malware_spread_scenario
from sim.scenarios.dos_attack import dos_attack_scenario
from sim.scenarios.bruteforce_attack import bruteforce_attack_scenario

# simulate multiple types of attacks happening at the same time
def multi_attack_scenario(engine) -> List[SimEvent]:

    events: List[SimEvent] = []

    # set overall intensity to high since multiple attacks can happen
    engine.intensity = "high"

    # track which attacks are active in this tick
    engine.active_attacks = []

    # each attack has a random chance to happen on every tick
    # malware spread (most likely)
    if engine.rng.random() < 0.6:
        engine.active_attacks.append("malware")
        events += malware_spread_scenario(engine)

    # dos attack
    if engine.rng.random() < 0.4:
        engine.active_attacks.append("dos")
        events += dos_attack_scenario(engine)

    # brute force attack
    if engine.rng.random() < 0.3:
        engine.active_attacks.append("bruteforce")
        events += bruteforce_attack_scenario(engine)

    # return all generated events from all active attacks
    return events