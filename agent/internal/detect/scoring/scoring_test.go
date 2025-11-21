package scoring

import "testing"

func TestCalculateUsesTagsAndHints(t *testing.T) {
	hints := ScoreHints{Category: "webshell"}
	score := Calculate("random", hints, nil)
	if score.Level != "Critical" {
		t.Fatalf("expected Critical level, got %s", score.Level)
	}
	if score.Breakdown.Severity != 3.3 {
		t.Fatalf("unexpected severity: %v", score.Breakdown.Severity)
	}
}

func TestCalculateFallsBackToRuleName(t *testing.T) {
	score := Calculate("coinminer_payload", ScoreHints{}, []string{"misc"})
	if score.Breakdown.Severity != 2.5 {
		t.Fatalf("expected coinminer profile")
	}
	if score.Level == "" {
		t.Fatalf("level should not be empty")
	}
}

func TestResolveRemediationSwitchesByCategory(t *testing.T) {
	plan := ResolveRemediation("ransom_sample", []string{})
	if plan.Priority != "critical" {
		t.Fatalf("expected critical priority, got %s", plan.Priority)
	}
	if len(plan.Steps) == 0 {
		t.Fatalf("expected remediation steps")
	}

	generic := ResolveRemediation("generic", []string{})
	if generic.Priority == "" || len(generic.Steps) == 0 {
		t.Fatalf("generic remediation missing data")
	}
}
