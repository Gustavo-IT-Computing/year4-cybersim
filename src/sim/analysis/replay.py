def print_attack_chain(engine):

    print("\n=== ATTACK CHAIN ===")

    #  loop through infection edges
    for src, tgt, tick in engine.infection_edges:
        #  display infection path with tick
        print(f"Tick {tick}: {src} → {tgt}")