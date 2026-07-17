// Package routing implements WG's in-memory smart-routing policy engine.
//
// AUTO is a management state, not a data-plane action. A Decision in AUTO
// mode therefore also carries the effective TUNNEL, DIRECT, or BLOCK action
// selected by the automatic classifier.
package routing

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Action is either a concrete forwarding action or the AUTO management state.
type Action string

const (
	ActionTunnel Action = "TUNNEL"
	ActionDirect Action = "DIRECT"
	ActionBlock  Action = "BLOCK"
	ActionAuto   Action = "AUTO"
)

var (
	ErrInvalidAction = errors.New("routing: invalid action")
	ErrInvalidTarget = errors.New("routing: invalid target")
	ErrAutoRule      = errors.New("routing: AUTO is not a persistent rule; delete the manual rule instead")
)

// ParseAction normalizes a user-facing action name.
func ParseAction(value string) (Action, error) {
	action := Action(strings.ToUpper(strings.TrimSpace(value)))
	if !action.valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidAction, value)
	}
	return action, nil
}

func (a Action) valid() bool {
	return a == ActionTunnel || a == ActionDirect || a == ActionBlock || a == ActionAuto
}

func (a Action) effective() bool {
	return a == ActionTunnel || a == ActionDirect || a == ActionBlock
}

// TargetKind identifies the normalized form of a routing target.
type TargetKind string

const (
	TargetDomain TargetKind = "DOMAIN"
	TargetIP     TargetKind = "IP"
	TargetCIDR   TargetKind = "CIDR"
)

// Target is a normalized exact domain, IP address, or CIDR prefix.
// Value is safe to persist or display. Internal parsed address fields are kept
// private so callers cannot corrupt matching state.
type Target struct {
	Kind  TargetKind
	Value string

	addr   netip.Addr
	prefix netip.Prefix
}

// ParseTarget validates and canonicalizes a domain, IP address, or CIDR.
func ParseTarget(value string) (Target, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Target{}, fmt.Errorf("%w: empty value", ErrInvalidTarget)
	}

	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return Target{}, fmt.Errorf("%w: malformed CIDR %q", ErrInvalidTarget, value)
		}
		prefix, err = canonicalPrefix(prefix)
		if err != nil {
			return Target{}, err
		}
		return Target{Kind: TargetCIDR, Value: prefix.String(), prefix: prefix}, nil
	}

	if addr, err := netip.ParseAddr(value); err == nil {
		addr = addr.Unmap()
		return Target{Kind: TargetIP, Value: addr.String(), addr: addr}, nil
	}

	domain, err := normalizeDomain(value)
	if err != nil {
		return Target{}, err
	}
	return Target{Kind: TargetDomain, Value: domain}, nil
}

func canonicalPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if prefix.Addr().Is4In6() {
		bits := prefix.Bits() - 96
		if bits < 0 || bits > 32 {
			return netip.Prefix{}, fmt.Errorf("%w: invalid IPv4-mapped prefix", ErrInvalidTarget)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
	}
	return prefix.Masked(), nil
}

func normalizeDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
	}
	if value == "" || len(value) > 253 || strings.HasSuffix(value, ".") {
		return "", fmt.Errorf("%w: malformed domain", ErrInvalidTarget)
	}

	for _, r := range value {
		if r > 127 {
			return "", fmt.Errorf("%w: domain must be IDNA ASCII", ErrInvalidTarget)
		}
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: malformed domain label", ErrInvalidTarget)
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("%w: malformed domain character", ErrInvalidTarget)
			}
		}
	}
	return value, nil
}

// Source describes who selected a decision. Callers cannot supply a Source to
// SetRule; returned Rule and Decision values are detached snapshots.
type Source string

const (
	SourceManual    Source = "MANUAL"
	SourceAutomatic Source = "AUTOMATIC"
)

// Rule is a detached snapshot of a persistent manual override.
type Rule struct {
	ID        uint64
	Target    Target
	Action    Action
	Source    Source
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Decision explains both the management state and concrete forwarding action.
// Action is AUTO when no manual override applies. EffectiveAction is always a
// concrete data-plane action.
type Decision struct {
	Target          Target
	Action          Action
	EffectiveAction Action
	Source          Source
	Reason          string
	MatchedRule     *Rule
	Generation      uint64
}

// AutoDecider selects a concrete action for a target without a manual rule.
// It must return TUNNEL, DIRECT, or BLOCK. Engine falls back safely if it does
// not. Implementations should be concurrency-safe because Explain may run in
// parallel.
type AutoDecider func(Target) (Action, string)

// Option configures an Engine before it is shared by callers.
type Option func(*Engine)

// WithAutoDecider installs the automatic classifier.
func WithAutoDecider(decider AutoDecider) Option {
	return func(engine *Engine) {
		if decider != nil {
			engine.decider = decider
		}
	}
}

// WithDefaultAction changes the safe action used when no classifier applies or
// a classifier returns an invalid action. AUTO is ignored.
func WithDefaultAction(action Action) Option {
	return func(engine *Engine) {
		if action.effective() {
			engine.defaultAction = action
		}
	}
}

// Engine is an in-memory, concurrency-safe manual policy store and evaluator.
type Engine struct {
	mu            sync.RWMutex
	rules         map[string]Rule
	nextID        uint64
	generation    uint64
	defaultAction Action
	decider       AutoDecider
	now           func() time.Time
}

// NewEngine returns an empty routing engine. The default automatic result is
// TUNNEL, matching WG's fail-closed unclassified policy.
func NewEngine(options ...Option) *Engine {
	engine := &Engine{
		rules:         make(map[string]Rule),
		defaultAction: ActionTunnel,
		now:           time.Now,
	}
	for _, option := range options {
		if option != nil {
			option(engine)
		}
	}
	return engine
}

// SetRule creates or atomically replaces a manual rule. Source is assigned by
// the engine and cannot be supplied by the caller. AUTO is represented by
// deleting a manual rule, not by persisting an AUTO rule.
func (e *Engine) SetRule(targetValue string, action Action) (Rule, error) {
	if !action.valid() {
		return Rule{}, fmt.Errorf("%w: %q", ErrInvalidAction, action)
	}
	if action == ActionAuto {
		return Rule{}, ErrAutoRule
	}
	target, err := ParseTarget(targetValue)
	if err != nil {
		return Rule{}, err
	}

	key := targetKey(target)
	e.mu.Lock()
	defer e.mu.Unlock()

	if existing, ok := e.rules[key]; ok {
		if existing.Action == action {
			return existing, nil
		}
		existing.Action = action
		existing.UpdatedAt = e.now().UTC()
		e.rules[key] = existing
		e.generation++
		return existing, nil
	}

	now := e.now().UTC()
	e.nextID++
	rule := Rule{
		ID:        e.nextID,
		Target:    target,
		Action:    action,
		Source:    SourceManual,
		CreatedAt: now,
		UpdatedAt: now,
	}
	e.rules[key] = rule
	e.generation++
	return rule, nil
}

// DeleteRule removes the exact manual target, if present, and returns the new
// explainable decision. If the last matching manual source disappears, the
// returned decision is in AUTO mode.
func (e *Engine) DeleteRule(targetValue string) (Decision, error) {
	target, err := ParseTarget(targetValue)
	if err != nil {
		return Decision{}, err
	}

	e.mu.Lock()
	key := targetKey(target)
	if _, ok := e.rules[key]; ok {
		delete(e.rules, key)
		e.generation++
	}
	e.mu.Unlock()

	return e.Explain(target.Value)
}

// List returns a stable, detached snapshot sorted by target kind and value.
func (e *Engine) List() []Rule {
	e.mu.RLock()
	rules := make([]Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	e.mu.RUnlock()

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Target.Kind == rules[j].Target.Kind {
			return rules[i].Target.Value < rules[j].Target.Value
		}
		return rules[i].Target.Kind < rules[j].Target.Kind
	})
	return rules
}

// Generation changes only when the effective manual rule set changes.
func (e *Engine) Generation() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.generation
}

// Explain evaluates a target against exact domain/IP rules, then longest CIDR
// prefix, then the automatic classifier. The returned explanation is a
// consistent snapshot at Generation even if a later concurrent mutation occurs.
func (e *Engine) Explain(targetValue string) (Decision, error) {
	target, err := ParseTarget(targetValue)
	if err != nil {
		return Decision{}, err
	}

	e.mu.RLock()
	rule, matched := e.matchLocked(target)
	generation := e.generation
	decider := e.decider
	defaultAction := e.defaultAction
	e.mu.RUnlock()

	if matched {
		copyOfRule := rule
		return Decision{
			Target:          target,
			Action:          rule.Action,
			EffectiveAction: rule.Action,
			Source:          SourceManual,
			Reason:          manualReason(rule, target),
			MatchedRule:     &copyOfRule,
			Generation:      generation,
		}, nil
	}

	action := defaultAction
	reason := "no manual override matched; unclassified targets default to TUNNEL"
	if decider != nil {
		classified, classifiedReason := decider(target)
		if classified.effective() {
			action = classified
			if strings.TrimSpace(classifiedReason) != "" {
				reason = classifiedReason
			} else {
				reason = "automatic classifier selected " + string(classified)
			}
		} else {
			reason = "automatic classifier returned an invalid action; safe default applied"
		}
	} else if defaultAction != ActionTunnel {
		reason = "no manual override matched; configured automatic default applied"
	}

	return Decision{
		Target:          target,
		Action:          ActionAuto,
		EffectiveAction: action,
		Source:          SourceAutomatic,
		Reason:          reason,
		Generation:      generation,
	}, nil
}

func (e *Engine) matchLocked(target Target) (Rule, bool) {
	if rule, ok := e.rules[targetKey(target)]; ok {
		return rule, true
	}
	if target.Kind != TargetIP {
		return Rule{}, false
	}

	var best Rule
	bestBits := -1
	for _, rule := range e.rules {
		if rule.Target.Kind != TargetCIDR || !rule.Target.prefix.Contains(target.addr) {
			continue
		}
		if bits := rule.Target.prefix.Bits(); bits > bestBits {
			best = rule
			bestBits = bits
		}
	}
	return best, bestBits >= 0
}

func targetKey(target Target) string {
	return string(target.Kind) + "\x00" + target.Value
}

func manualReason(rule Rule, target Target) string {
	if rule.Target.Kind == TargetCIDR && target.Kind == TargetIP {
		return fmt.Sprintf("manual CIDR override %s matched by longest prefix", rule.Target.Value)
	}
	return fmt.Sprintf("manual %s override matched exactly", strings.ToLower(string(rule.Target.Kind)))
}
