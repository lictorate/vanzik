package main

import "testing"

// A new connection preselects "Block them"; reconnecting keeps the mode the
// agent already has, so a deliberate fail-open choice isn't flipped.
func TestSetupPreselectsFailClosedForNewConnections(t *testing.T) {
	serverUp(t)
	m := testMachine(t)
	const title = "If Vanzik isn't running"
	boot := &setup{m: m, ui: &scriptedUI{t: t, choices: []int{0, 0, 1}}, svc: &fakeService{}}
	boot.doSetup() // writes the policy and state, as the other flow tests do
	for _, a := range agentIntegrations {
		ui := &scriptedUI{t: t}
		s := &setup{m: m, ui: ui, svc: &fakeService{}, state: boot.state}
		connect := func(choices ...int) int {
			ui.choices = choices
			s.connectAgent(a)
			return ui.defs[title]
		}
		if def := connect(0, 0); def != 1 { // add rules; let calls through
			t.Errorf("%s: new connection preselects option %d, want 1 (block)", a.name, def)
		}
		if def := connect(0); def != 0 { // has rules now; stays fail-open
			t.Errorf("%s: reconnecting a fail-open hook preselects %d, want 0", a.name, def)
		}
		if def := connect(1); def != 0 {
			t.Errorf("%s: want 0 before switching to block, got %d", a.name, def)
		}
		if def := connect(1); def != 1 {
			t.Errorf("%s: reconnecting a fail-closed hook preselects %d, want 1", a.name, def)
		}
		if _, fc := a.connected(); !fc {
			t.Errorf("%s: not fail-closed after choosing Block", a.name)
		}
	}
}
