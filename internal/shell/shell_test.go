package shell

import (
	"os/exec"
	"strings"
	"testing"
)

func TestWriteEnvRoundTripsThroughShell(t *testing.T) {
	tricky := `it's a "test" $HOME \n`
	for _, sh := range []string{"bash", "fish"} {
		if _, err := exec.LookPath(sh); err != nil {
			t.Logf("skipping %s: not installed", sh)
			continue
		}
		var b strings.Builder
		syntax, _ := Normalize(sh)
		if err := WriteEnv(&b, syntax, map[string]string{"VAULT_ADDR": tricky}); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(sh, "-c", b.String()+` printf %s "$VAULT_ADDR"`).Output()
		if err != nil {
			t.Fatalf("%s: %v", sh, err)
		}
		if string(out) != tricky {
			t.Errorf("%s: got %q, want %q", sh, out, tricky)
		}
	}
}

func TestWriteEnvUnsetsMissing(t *testing.T) {
	var b strings.Builder
	WriteEnv(&b, POSIX, map[string]string{"VAULT_ADDR": "x"})
	if !strings.Contains(b.String(), "unset VAULT_TOKEN;") {
		t.Errorf("expected VAULT_TOKEN to be unset:\n%s", b.String())
	}
}
