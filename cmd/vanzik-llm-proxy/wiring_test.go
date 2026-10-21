package main

// wiring_test.go guards the single most consequential line in this binary:
// `server.PolicyCheck = gate.Check`.
//
// A Server with no PolicyCheck ALLOWS every tool call (llmproxy's nil-safe
// default, pinned in pkg/llmproxy/policy_hook_contract_test.go), leaving
// only an `allow:llm_api_proxy:no_hook` rule string as a trace. Nothing
// refuses to serve unwired, so every code path must assign the hook.
//
// A structural test because main() is not callable: permissive about
// names, ordering and extra branches, strict that no path constructs a
// policy gate without wiring it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

// gateConstructor builds the policy gate. A rename makes these tests fail
// loudly; update this constant with it.
const gateConstructor = "NewHTTPPolicyClient"

// hookField is the Server field that must receive the gate.
const hookField = "PolicyCheck"

func parseMain(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "main.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, f
}

// containsGateConstruction reports whether n contains a call to the gate
// constructor anywhere beneath it.
func containsGateConstruction(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == gateConstructor {
			found = true
			return false
		}
		return true
	})
	return found
}

// countHookAssignments counts assignments whose left-hand side is a selector
// ending in the hook field (e.g. `bridge.PolicyCheck = ...`).
func countHookAssignments(f *ast.File) int {
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == hookField {
				n++
			}
		}
		return true
	})
	return n
}

// TestMain_WiresPolicyCheck: the hook is assigned at all.
func TestMain_WiresPolicyCheck(t *testing.T) {
	_, f := parseMain(t)

	if got := countHookAssignments(f); got == 0 {
		t.Fatalf("main.go never assigns .%s — a Server with no policy hook ALLOWS every "+
			"tools/call, and nothing at startup refuses to serve in that state", hookField)
	}
	if !containsGateConstruction(f) {
		t.Fatalf("main.go never calls %s; if the gate constructor was renamed, update the "+
			"gateConstructor constant in this test so the wiring invariant keeps being checked",
			gateConstructor)
	}
}

// TestMain_EveryBranchConstructingAGateHasASibling: if any arm of an
// if/else constructs a policy gate, every arm must, including the final
// else. Catches a new branch (another policy source, a shortcut) that
// builds no gate.
func TestMain_EveryBranchConstructingAGateHasASibling(t *testing.T) {
	fset, f := parseMain(t)

	checked := 0
	ast.Inspect(f, func(node ast.Node) bool {
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		bodyHasGate := containsGateConstruction(ifStmt.Body)
		if !bodyHasGate && (ifStmt.Else == nil || !containsGateConstruction(ifStmt.Else)) {
			return true // this if/else has nothing to do with the gate
		}
		checked++
		pos := fset.Position(ifStmt.Pos())

		if ifStmt.Else == nil {
			t.Errorf("%s: an if-branch constructs the policy gate but has no else — "+
				"the else-path reaches Run() with no gate, so every tool call is allowed unevaluated (B5)", pos)
			return true
		}
		elseHasGate := containsGateConstruction(ifStmt.Else)
		if bodyHasGate != elseHasGate {
			which := "else"
			if !bodyHasGate {
				which = "if"
			}
			t.Errorf("%s: the %s branch constructs no policy gate while its sibling does — "+
				"requests taking that path would be forwarded with no policy evaluation (B5)", pos, which)
		}
		return true
	})

	if checked == 0 {
		t.Fatalf("found no if/else that constructs the policy gate; the wiring shape changed and "+
			"this invariant is no longer being checked — re-derive it against main.go (%s)",
			fset.Position(f.Pos()).Filename)
	}
}

// countHookAssignmentsIn counts hook assignments beneath a single node.
func countHookAssignmentsIn(n ast.Node) int {
	count := 0
	ast.Inspect(n, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == hookField {
				count++
			}
		}
		return true
	})
	return count
}

// TestMain_HookWiringIsUniformAcrossGateBranches: a branch can build a
// gate and forget to assign it, which construction parity misses. Two
// wiring shapes are legitimate:
//
//	per-branch  — each arm assigns the hook itself (vanzik-mcp-gateway)
//	post-branch — arms only build the gate; one assignment follows the if/else
//	              (this binary)
//
// A mixture is not: an arm that builds without wiring reaches Run() with a
// nil hook and allows everything. So the rule is all-or-nothing.
func TestMain_HookWiringIsUniformAcrossGateBranches(t *testing.T) {
	fset, f := parseMain(t)

	type arm struct {
		node ast.Node
		pos  token.Pos
	}
	var arms []arm
	ast.Inspect(f, func(node ast.Node) bool {
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		if containsGateConstruction(ifStmt.Body) {
			arms = append(arms, arm{ifStmt.Body, ifStmt.Body.Pos()})
		}
		if ifStmt.Else != nil && containsGateConstruction(ifStmt.Else) {
			arms = append(arms, arm{ifStmt.Else, ifStmt.Else.Pos()})
		}
		return true
	})

	if len(arms) == 0 {
		t.Fatal("no branch constructs the policy gate; the wiring shape changed and this " +
			"invariant is no longer being checked — re-derive it against main.go")
	}

	var wired, bare []string
	for _, a := range arms {
		if countHookAssignmentsIn(a.node) > 0 {
			wired = append(wired, fset.Position(a.pos).String())
		} else {
			bare = append(bare, fset.Position(a.pos).String())
		}
	}

	// All-or-nothing. A mixture means at least one path runs unwired.
	if len(wired) > 0 && len(bare) > 0 {
		t.Errorf("policy-hook wiring is inconsistent across gate-constructing branches: "+
			"wired at %v but NOT at %v. The un-wired path reaches Run() with a nil hook, "+
			"which ALLOWS every request unevaluated. Either wire every branch, "+
			"or wire once after the if/else — not a mixture.", wired, bare)
	}

	// The post-branch shape is only safe if the assignment actually exists.
	if len(wired) == 0 && countHookAssignments(f) == 0 {
		t.Error("no branch wires the policy hook and there is no assignment after the " +
			"if/else either — nothing ever wires it")
	}
}
