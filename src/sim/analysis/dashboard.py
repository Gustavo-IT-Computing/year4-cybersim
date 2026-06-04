import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# this function runs the visual dashboard of the simulation
# it shows the network, infection curve, and some live info
def run_dashboard(engine, db):

    G = nx.Graph()

    # add all nodes from the network into the graph
    for node in engine.network.nodes:
        G.add_node(node)

    # add connections between nodes
    for node, neighbors in engine.network.edges.items():
        for n in neighbors:
            G.add_edge(node, n)

    # define positions for nodes so the layout stays consistent
    pos = nx.spring_layout(G, k=1.2, seed=42)

    # create the main figure
    fig = plt.figure(figsize=(15, 9))

    # divide the screen into 3 areas
    ax_network = plt.subplot2grid((2, 3), (0, 0), colspan=2)
    ax_curve = plt.subplot2grid((2, 3), (1, 0), colspan=2)
    ax_info = plt.subplot2grid((2, 3), (0, 2), rowspan=2)

    # get infection edges if they exist
    infection_edges = getattr(engine, "infection_edges", [])

    # this function updates the dashboard on each frame
    def update(frame):

        # clear previous frame
        ax_network.clear()
        ax_curve.clear()
        ax_info.clear()

        # get snapshot of current state and metrics
        snapshot = engine.state_history[frame]
        metrics = engine.history[frame]

        colors = []

        # decide color of each node based on its state
        for node in G.nodes():
            state = str(snapshot.get(node, "clean")).lower()
            node_obj = engine.network.nodes[node]

            if "infected" in state:
                colors.append("red")
            elif "quarantined" in state:
                colors.append("orange")
            elif "patched" in state:
                colors.append("blue")
            else:
                # green if low risk, yellow if higher risk
                colors.append("green" if node_obj.risk_score < 0.5 else "yellow")

        # draw the network graph
        nx.draw(G,pos,ax=ax_network,node_color=colors,with_labels=True,node_size=650,font_size=8)

        # highlight recent infection connections for a few frames
        for src, tgt, tick in infection_edges:
            if frame - tick < 3:
                nx.draw_networkx_edges(G, pos,edgelist=[(src, tgt)],edge_color="red",width=2,ax=ax_network)

        # title showing current tick and attack type
        ax_network.set_title(
            f"Tick {frame + 1} | Attack: {engine.current_attack.upper()}",
            fontsize=12
        )

        # plot infected nodes over time
        curve = [h["infected"] for h in engine.history]
        ax_curve.plot(curve[:frame + 1])
        ax_curve.set_title("Infected Nodes Over Time")

        # hide axis for info panel
        ax_info.axis("off")

        # get threat intelligence info if available
        intel = getattr(engine, "threat_intel", {})

        # threat intelligence section
        ax_info.text(0.0, 0.95, "Threat Intelligence", fontsize=11, weight="bold")

        ax_info.text(
            0.0, 0.88,
            f"Origin: {intel.get('origin_node', 'Unknown')}\n"
            f"Attack: {intel.get('attack_type', 'Unknown')}\n"
            f"Vector: {intel.get('vector', 'Unknown')}",
            fontsize=10
        )

        # network status section
        ax_info.text(0.0, 0.78, "Network Status", fontsize=11, weight="bold")

        ax_info.text(
            0.0, 0.66,
            f"Nodes: {metrics['total_nodes']}\n"
            f"Infected: {metrics['infected']}\n"
            f"Quarantined: {metrics['quarantined']}\n"
            f"Patched: {metrics['patched']}\n"
            f"Risk Score: {metrics['risk']:.2f}",
            fontsize=10
        )

        # current attack phase
        phase = engine.get_attack_phase(metrics)

        # recent AI detections for current frame
        ax_info.text(0.0, 0.38, "Recent Detections", fontsize=11, weight="bold")

        y = 0.31

        recent_detections = [
            d for d in getattr(engine, "ai_decisions", [])
            if 0 <= (frame + 1) - d["tick"] <= 5
        ]

        last_explanation = None

        if recent_detections:

            # show newest detections first
            recent_detections = recent_detections[-3:]

            for d in reversed(recent_detections):
                reason = d["reasons"][0] if d["reasons"] else "Suspicious activity"

                ax_info.text(
                    0.0,
                    y,
                    f"{d['node']} → {reason}",
                    fontsize=9
                )

                y -= 0.05

            # latest AI explanation
            last_explanation = recent_detections[-1]

        else:
            ax_info.text(0.0, y, "No recent threats", fontsize=9)

        ax_info.text(0.0, 0.54, "Attack Phase", fontsize=11, weight="bold")

        ax_info.text(
            0.0,
            0.46,
            phase,
            fontsize=10
        )

        # show ai explanation if available
        if last_explanation:
            reasons = "\n".join(f"- {r}" for r in last_explanation["reasons"][:2])

            ax_info.text(0.0,0.08,
                f"AI Explanation\n"
                f"Confidence: {last_explanation['confidence']}%\n"
                f"{reasons}",fontsize=8,
                bbox=dict(boxstyle="round",facecolor="lightblue",alpha=0.6)
            )

    plt.pause(0.01)

    # create animation that updates every frame
    anim = FuncAnimation(fig,update,frames=len(engine.state_history),interval=700,repeat=False)

    plt.show()
    return anim
