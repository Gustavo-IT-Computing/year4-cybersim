from sim.scenarios.malware_spread import malware_spread_scenario
from sim.scenarios.multi_attack import multi_attack_scenario

# Define available simulation scenarios and their configurations
SCENARIOS = {
    "baseline": {
        "attack": "malware",  # default malware attack
        "defense": "hybrid",  # combined defense strategies
        "fn": malware_spread_scenario  # function to execute
    },
    "no_defense": {
        "attack": "malware",
        "defense": "none",  # no protection applied
        "fn": malware_spread_scenario
    },
    "advanced": {
        "attack": "multi",  # random mix of attacks
        "defense": "hybrid",
        "fn": multi_attack_scenario
    }
}

# Retrieve scenario configuration by name
def get_scenario(name: str):
    # validate scenario name
    if name not in SCENARIOS:
        raise ValueError(f"Invalid scenario: {name}")

    return SCENARIOS[name]  # return selected scenario config