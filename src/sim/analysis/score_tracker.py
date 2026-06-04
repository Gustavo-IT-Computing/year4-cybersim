class ScoreTracker:

    def __init__(self, total_nodes):

        # overall score of the simulation
        self.score = 0

        # store all decisions made during the run
        self.decisions = []

        self.total_nodes = total_nodes

        # highest number of infected nodes reached
        self.peak_infected = 0

        # decision statistics
        self.total_decisions = 0
        self.good_decisions = 0

        # tick when first action was taken
        self.first_response_tick = None

        # final grade
        self.grade = "F"

    # update peak infection if current is higher
    def update_peak(self, infected):

        if infected > self.peak_infected:
            self.peak_infected = infected

    # evaluate if a decision improved the situation
    def evaluate_decision(
        self,
        before,
        after,
        tick,
        confidence=50
    ):

        self.total_decisions += 1

        # compare before and after
        diff = before - after

        # infections reduced
        if diff > 0:

            self.good_decisions += 1
            result = "GOOD"

            self.score += 10

        # infections increased
        elif diff < 0:

            result = "BAD"

            self.score -= 10

        # no visible change
        else:

            result = "NEUTRAL"

            # adjust score based on AI confidence
            if confidence > 80:
                self.score -= 5

            elif confidence < 40:
                self.score += 2

            else:
                self.score -= 2

        # record first response tick
        if self.first_response_tick is None:
            self.first_response_tick = tick

        # save decision history
        self.decisions.append({
            "tick": tick,
            "before": before,
            "after": after,
            "impact": diff,
            "result": result,
            "confidence": confidence
        })

    # final scoring at end of simulation
    def finalize(self, final_metrics):

        score = 0

        # reward based on final infected count
        if final_metrics["infected"] == 0:
            score += 40

        elif final_metrics["infected"] < 5:
            score += 25

        else:
            score += 10

        # reward based on peak infection
        if self.peak_infected < 10:
            score += 20

        elif self.peak_infected < 20:
            score += 10

        # reward based on decision quality
        if self.total_decisions > 0:

            ratio = (
                self.good_decisions
                / self.total_decisions
            )

            if ratio > 0.7:
                score += 25

            elif ratio > 0.4:
                score += 15

            else:
                score -= 10

        # reward faster reactions
        if self.first_response_tick is not None:

            if self.first_response_tick <= 3:
                score += 15

            elif self.first_response_tick <= 6:
                score += 10

            else:
                score += 5

        # add to running score
        self.score += score

        # convert score to grade
        if self.score >= 85:
            self.grade = "A"

        elif self.score >= 70:
            self.grade = "B"

        elif self.score >= 55:
            self.grade = "C"

        elif self.score >= 40:
            self.grade = "D"

        else:
            self.grade = "F"