package access

import (
	"os"
	"strconv"
	"testing"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		in   string
		want Mode
		ok   bool
	}{
		{"", Solo, true},
		{"solo", Solo, true},
		{"group", Group, true},
		{"all", All, true},
		{"everyone", Solo, false},
		{"GROUP", Solo, false},
	}
	for _, tt := range tests {
		got, err := ParseMode(tt.in)
		if (err == nil) != tt.ok {
			t.Errorf("ParseMode(%q) error = %v, want ok=%v", tt.in, err, tt.ok)
			continue
		}
		if tt.ok && got != tt.want {
			t.Errorf("ParseMode(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestPermissions(t *testing.T) {
	tests := []struct {
		mode      Mode
		dir, sock os.FileMode
	}{
		{Solo, 0o700, 0o700},
		{Group, 0o750, 0o770},
		{All, 0o755, 0o777},
	}
	for _, tt := range tests {
		p := Policy{Mode: tt.mode}
		if got := p.DirPerm(); got != tt.dir {
			t.Errorf("%v DirPerm = %#o, want %#o", tt.mode, got, tt.dir)
		}
		if got := p.SocketPerm(); got != tt.sock {
			t.Errorf("%v SocketPerm = %#o, want %#o", tt.mode, got, tt.sock)
		}
		// Only the owner may ever write to the directory, or another user
		// could replace the sockets.
		if p.DirPerm()&0o022 != 0 {
			t.Errorf("%v DirPerm %#o is writable by group or others", tt.mode, p.DirPerm())
		}
	}
}

func TestZeroPolicyIsSolo(t *testing.T) {
	var p Policy
	if p.Mode != Solo {
		t.Errorf("zero Policy mode = %v, want solo", p.Mode)
	}
}

func TestLookupGroupAcceptsNumericGID(t *testing.T) {
	gid := os.Getgid()
	got, err := LookupGroup(strconv.Itoa(gid))
	if err != nil {
		t.Skipf("own gid %d not resolvable here: %v", gid, err)
	}
	if got != gid {
		t.Errorf("LookupGroup(%d) = %d", gid, got)
	}
}

func TestLookupGroupRejectsUnknown(t *testing.T) {
	if _, err := LookupGroup("no-such-group-cipherstore-test"); err == nil {
		t.Error("LookupGroup accepted an unknown group")
	}
}
