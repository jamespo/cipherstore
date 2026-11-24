package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain points the default config file at an empty directory, so tests
// that call Run never read the config of the user running them.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cipherstore-cli-test")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CONFIG_HOME", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cipherstore.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	path := writeConfig(t, `
mode = "group"
group = "wheel"
socketpath = "/srv/cipherstore"
dbpath = "~/vault"
`)
	cfg, err := loadConfig(path, true)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	want := fileConfig{Mode: "group", Group: "wheel", SocketPath: "/srv/cipherstore", DBPath: filepath.Join(home, "vault")}
	if cfg != want {
		t.Errorf("loadConfig = %+v, want %+v", cfg, want)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")
	if _, err := loadConfig(missing, false); err != nil {
		t.Errorf("missing default config: %v, want no error", err)
	}
	if _, err := loadConfig(missing, true); err == nil {
		t.Error("missing -config file accepted, want an error")
	}
}

func TestLoadConfigRejects(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key":   `sockpath = "/srv/cs"`,
		"relative path": `socketpath = "srv/cs"`,
		"wrong type":    `mode = 3`,
		"bad syntax":    `mode = `,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfig(writeConfig(t, body), true); err == nil {
				t.Error("loadConfig accepted it, want an error")
			}
		})
	}
}

func TestLoadConfigRejectsWritableByOthers(t *testing.T) {
	path := writeConfig(t, `mode = "all"`)
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(path, true)
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("loadConfig = %v, want a refusal of a group-writable file", err)
	}
}

func TestLoadConfigFollowsSymlink(t *testing.T) {
	target := writeConfig(t, `mode = "all"`)
	link := filepath.Join(t.TempDir(), "link.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(link, true)
	if err != nil || cfg.Mode != "all" {
		t.Errorf("loadConfig via symlink = %+v, %v", cfg, err)
	}
}

func TestCommandLineOverridesConfig(t *testing.T) {
	path := writeConfig(t, `
mode = "group"
group = "no-such-group-cipherstore-test"
socketpath = "/srv/cs"
dbpath = "/srv/db"
`)
	o, _, err := parseGlobal([]string{"-config", path, "-mode", "solo", "-dbpath", "/other", "status"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	o, err = withConfig(o)
	if err != nil {
		t.Fatalf("withConfig: %v", err)
	}
	if o.mode != "solo" || o.dbPath != "/other" || o.socketPath != "/srv/cs" {
		t.Errorf("merged options = %+v", o)
	}
	// The config's group belongs to group mode, which the command line
	// overrode, so it must be dropped rather than rejected.
	if o.group != "" {
		t.Errorf("group = %q, want it dropped outside group mode", o.group)
	}
	if _, err := layoutFor(o); err != nil {
		t.Errorf("layoutFor: %v", err)
	}
}

func TestConfigGroupAppliesInGroupMode(t *testing.T) {
	path := writeConfig(t, "mode = \"group\"\ngroup = \"staff\"\n")
	o, _, _ := parseGlobal([]string{"-config", path, "status"}, io.Discard)
	o, err := withConfig(o)
	if err != nil {
		t.Fatal(err)
	}
	if o.mode != "group" || o.group != "staff" {
		t.Errorf("merged options = %+v", o)
	}
}

func TestEmptyConfigFlagDisablesConfig(t *testing.T) {
	// Even a broken default config is not read with -config "".
	if err := os.WriteFile(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "cipherstore.toml"), []byte("bogus ="), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "cipherstore.toml")) })

	o, _, _ := parseGlobal([]string{"-config", "", "status"}, io.Discard)
	if _, err := withConfig(o); err != nil {
		t.Errorf("withConfig with -config \"\": %v", err)
	}
	o, _, _ = parseGlobal([]string{"status"}, io.Discard)
	if _, err := withConfig(o); err == nil {
		t.Error("broken default config was not reported")
	}
}

func TestRequireOwnerAllowsOwnDaemon(t *testing.T) {
	e, _, _ := newEnv(t, "")
	if err := e.requireOwner("stop"); err != nil {
		t.Errorf("requireOwner on our own directory: %v", err)
	}
}
