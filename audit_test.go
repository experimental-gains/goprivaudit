package main

import (
	"reflect"
	"testing"
)

func TestAuditSumdbLeak(t *testing.T) {
	modules := []string{
		"github.com/myorg/internal-tool",
		"github.com/pkg/errors",
	}
	privatePrefixes := []string{"github.com/myorg"}
	gonosumdb := []string{} // not covered at all

	r := audit(modules, privatePrefixes, gonosumdb)
	want := []string{"github.com/myorg/internal-tool"}
	if !reflect.DeepEqual(r.SumdbLeaks, want) {
		t.Errorf("SumdbLeaks = %v, want %v", r.SumdbLeaks, want)
	}
	if r.Clean() {
		t.Error("expected Clean() == false")
	}
}

func TestAuditCoveredNoLeak(t *testing.T) {
	modules := []string{"github.com/myorg/internal-tool"}
	privatePrefixes := []string{"github.com/myorg"}
	gonosumdb := []string{"github.com/myorg/*"}

	r := audit(modules, privatePrefixes, gonosumdb)
	if len(r.SumdbLeaks) != 0 {
		t.Errorf("expected no leaks, got %v", r.SumdbLeaks)
	}
	if !r.Clean() {
		t.Error("expected Clean() == true")
	}
}

func TestAuditNoPrivateSignalNoFinding(t *testing.T) {
	modules := []string{"github.com/pkg/errors"}
	r := audit(modules, nil, nil)
	if !r.Clean() {
		t.Errorf("expected clean report for a module with no private-auth signal, got %+v", r)
	}
}

func TestAuditBroadPattern(t *testing.T) {
	r := audit(nil, nil, []string{"*"})
	want := []string{"*"}
	if !reflect.DeepEqual(r.BroadPatterns, want) {
		t.Errorf("BroadPatterns = %v, want %v", r.BroadPatterns, want)
	}
	if r.Clean() {
		t.Error("expected Clean() == false")
	}
}

func TestAuditDeduplicatesFindings(t *testing.T) {
	modules := []string{"github.com/myorg/a", "github.com/myorg/a"}
	r := audit(modules, []string{"github.com/myorg"}, nil)
	if len(r.SumdbLeaks) != 1 {
		t.Errorf("expected deduplicated single finding, got %v", r.SumdbLeaks)
	}
}
