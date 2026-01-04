package memscan

import "testing"

func TestIsRWXProtectHonorsGuardAndNoAccess(t *testing.T) {
	if !isRWXProtect(pageExecuteReadWrite) {
		t.Fatalf("expected execute-readwrite to match")
	}
	if !isRWXProtect(pageExecuteWriteCopy) {
		t.Fatalf("expected execute-writecopy to match")
	}
	if isRWXProtect(pageExecuteReadWrite | pageGuard) {
		t.Fatalf("guard pages should not match")
	}
	if isRWXProtect(pageExecuteReadWrite | pageNoAccess) {
		t.Fatalf("noaccess pages should not match")
	}
}

func TestIsReadableCommittedHonorsStateAndProtection(t *testing.T) {
	if isReadableCommitted(Region{State: 0, Protect: pageExecuteReadWrite}) {
		t.Fatalf("expected non-committed pages to be skipped")
	}
	if isReadableCommitted(Region{State: memCommit, Protect: 0}) {
		t.Fatalf("expected protect=0 pages to be skipped")
	}
	if isReadableCommitted(Region{State: memCommit, Protect: pageNoAccess}) {
		t.Fatalf("expected noaccess pages to be skipped")
	}
	if isReadableCommitted(Region{State: memCommit, Protect: pageExecuteReadWrite | pageGuard}) {
		t.Fatalf("expected guard pages to be skipped")
	}
	if !isReadableCommitted(Region{State: memCommit, Protect: 0x20}) {
		t.Fatalf("expected committed readable pages to match")
	}
}
