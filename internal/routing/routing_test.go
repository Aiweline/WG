package routing

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestParseTargetNormalizesKinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		kind  TargetKind
		value string
	}{
		{" Example.COM. ", TargetDomain, "example.com"},
		{"192.0.2.9", TargetIP, "192.0.2.9"},
		{"192.0.2.99/24", TargetCIDR, "192.0.2.0/24"},
		{"2001:db8::1", TargetIP, "2001:db8::1"},
		{"2001:db8::1234/64", TargetCIDR, "2001:db8::/64"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			target, err := ParseTarget(test.input)
			if err != nil {
				t.Fatalf("ParseTarget: %v", err)
			}
			if target.Kind != test.kind || target.Value != test.value {
				t.Fatalf("got (%s, %q), want (%s, %q)", target.Kind, target.Value, test.kind, test.value)
			}
		})
	}
}

func TestParseTargetRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"", "bad..example", "-bad.example", "*.example.com", "例子.example", "192.0.2.1/99"} {
		if _, err := ParseTarget(input); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("ParseTarget(%q) error = %v, want ErrInvalidTarget", input, err)
		}
	}
}

func TestSetExplainAndDeleteReturnsToAuto(t *testing.T) {
	t.Parallel()

	engine := NewEngine(WithAutoDecider(func(target Target) (Action, string) {
		return ActionDirect, "signed local prefix selected DIRECT"
	}))

	rule, err := engine.SetRule("Example.COM", ActionTunnel)
	if err != nil {
		t.Fatalf("SetRule: %v", err)
	}
	if rule.Source != SourceManual || rule.Target.Value != "example.com" {
		t.Fatalf("unexpected rule: %+v", rule)
	}

	decision, err := engine.Explain("example.com.")
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if decision.Action != ActionTunnel || decision.EffectiveAction != ActionTunnel || decision.Source != SourceManual {
		t.Fatalf("manual decision = %+v", decision)
	}
	if decision.MatchedRule == nil || decision.Reason == "" {
		t.Fatalf("manual decision is not explainable: %+v", decision)
	}

	decision, err = engine.DeleteRule("example.com")
	if err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if decision.Action != ActionAuto || decision.EffectiveAction != ActionDirect || decision.Source != SourceAutomatic {
		t.Fatalf("deleted decision = %+v, want AUTO/DIRECT/AUTOMATIC", decision)
	}
	if len(engine.List()) != 0 || engine.Generation() != 2 {
		t.Fatalf("rule was not deleted atomically: list=%v generation=%d", engine.List(), engine.Generation())
	}
}

func TestCIDRUsesLongestPrefixAndExactIPWins(t *testing.T) {
	t.Parallel()

	engine := NewEngine()
	mustSet(t, engine, "10.0.0.0/8", ActionDirect)
	mustSet(t, engine, "10.1.0.0/16", ActionTunnel)
	mustSet(t, engine, "10.1.2.3", ActionBlock)

	assertEffective(t, engine, "10.2.3.4", ActionDirect)
	assertEffective(t, engine, "10.1.9.9", ActionTunnel)
	decision := assertEffective(t, engine, "10.1.2.3", ActionBlock)
	if decision.MatchedRule == nil || decision.MatchedRule.Target.Kind != TargetIP {
		t.Fatalf("exact IP did not win: %+v", decision)
	}
}

func TestActionsAndAutoCannotBePersisted(t *testing.T) {
	t.Parallel()

	engine := NewEngine()
	for i, action := range []Action{ActionTunnel, ActionDirect, ActionBlock} {
		target := fmt.Sprintf("service-%d.example", i)
		if _, err := engine.SetRule(target, action); err != nil {
			t.Fatalf("SetRule(%s): %v", action, err)
		}
		assertEffective(t, engine, target, action)
	}
	if _, err := engine.SetRule("auto.example", ActionAuto); !errors.Is(err, ErrAutoRule) {
		t.Fatalf("SetRule(AUTO) error = %v, want ErrAutoRule", err)
	}
	if _, err := engine.SetRule("bad.example", Action("ALLOW")); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("SetRule(invalid) error = %v, want ErrInvalidAction", err)
	}
}

func TestReturnedSourcesAreDetachedAndGenerationIsIdempotent(t *testing.T) {
	t.Parallel()

	engine := NewEngine()
	rule := mustSet(t, engine, "copy.example", ActionBlock)
	firstGeneration := engine.Generation()
	if _, err := engine.SetRule("copy.example", ActionBlock); err != nil {
		t.Fatalf("idempotent SetRule: %v", err)
	}
	if engine.Generation() != firstGeneration {
		t.Fatalf("idempotent set changed generation: %d -> %d", firstGeneration, engine.Generation())
	}

	rule.Source = SourceAutomatic
	rules := engine.List()
	if len(rules) != 1 || rules[0].Source != SourceManual {
		t.Fatalf("caller mutated engine source: %+v", rules)
	}
	rules[0].Source = SourceAutomatic
	if engine.List()[0].Source != SourceManual {
		t.Fatal("List returned mutable internal state")
	}
}

func TestEngineConcurrentAccess(t *testing.T) {
	engine := NewEngine(WithAutoDecider(func(target Target) (Action, string) {
		return ActionDirect, "concurrent test classifier"
	}))

	var wait sync.WaitGroup
	for worker := 0; worker < 24; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				target := fmt.Sprintf("host-%d-%d.example", worker, iteration%8)
				if _, err := engine.SetRule(target, ActionTunnel); err != nil {
					t.Errorf("SetRule: %v", err)
					return
				}
				if _, err := engine.Explain(target); err != nil {
					t.Errorf("Explain: %v", err)
					return
				}
				_ = engine.List()
				_ = engine.Generation()
				if _, err := engine.DeleteRule(target); err != nil {
					t.Errorf("DeleteRule: %v", err)
					return
				}
			}
		}()
	}
	wait.Wait()
}

func mustSet(t *testing.T, engine *Engine, target string, action Action) Rule {
	t.Helper()
	rule, err := engine.SetRule(target, action)
	if err != nil {
		t.Fatalf("SetRule(%q, %s): %v", target, action, err)
	}
	return rule
}

func assertEffective(t *testing.T, engine *Engine, target string, want Action) Decision {
	t.Helper()
	decision, err := engine.Explain(target)
	if err != nil {
		t.Fatalf("Explain(%q): %v", target, err)
	}
	if decision.EffectiveAction != want {
		t.Fatalf("Explain(%q) = %+v, want effective action %s", target, decision, want)
	}
	return decision
}
