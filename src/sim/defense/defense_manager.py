from sim.defense.strategies import quarantine_strategy, patch_vulnerable_nodes

# Map each defense mode to the strategies that should be applied
DEFENSE_MAP = {
    "none": [], # no defense
    "quarantine": [quarantine_strategy], # isolate infected nodes
    "patch": [patch_vulnerable_nodes], # patch vulnerable nodes
    "hybrid": [quarantine_strategy, patch_vulnerable_nodes], # combine both strategies
}

def apply_defense(engine, mode):

    events = [] # Apply the selected defense strategies and return resulting events

    strategies = DEFENSE_MAP.get(mode, []) # getting the strategies for the selected mode

    for strategy in strategies: # execute each strategy and collect resulting events
        events.extend(strategy(engine))

    return events # return all defense events