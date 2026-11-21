package fuzz

import (
	"strings"
	"testing"
)

// TestBundledWordlistIsNonDestructive enforces the claim the fuzzing guide and
// the security model make: the bundled payloads probe, but never write, drop,
// delete or shell out to a destructive command. A single `DROP TABLE` in the
// list turned that claim into a contradiction once; this test keeps it honest.
func TestBundledWordlistIsNonDestructive(t *testing.T) {
	payloads, err := Payloads("default", Methods)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"drop table", "drop database", "delete from", "truncate table",
		"alter table", "create table", "insert into", "update ",
		"grant ", "revoke ",
		"rm -rf", "rm -f", "shutdown", "reboot", "mkfs", "dd if=",
		"format c:", "del /f", "rd /s", "chmod ", "chown ",
		"powershell -enc", "cmd.exe /c del",
	}
	for _, p := range payloads {
		lower := strings.ToLower(p.Text)
		for _, f := range forbidden {
			if strings.Contains(lower, f) {
				t.Errorf("bundled payload %q contains destructive fragment %q", p.Text, f)
			}
		}
	}
}
