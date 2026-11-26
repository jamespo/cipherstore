package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"

	"github.com/jamespo/cipherstore/internal/paths"
)

// fileConfig is the contents of the config file. Every key is optional and
// gives the default for the global option of the same name; an option given
// on the command line wins.
//
// mode and socketpath matter to every command, since the client must know
// where the daemon is and whether it may be another user's. group, fullaccess
// and dbpath are only used by `start`.
type fileConfig struct {
	Mode       string `toml:"mode"`
	Group      string `toml:"group"`
	FullAccess bool   `toml:"fullaccess"`
	SocketPath string `toml:"socketpath"`
	DBPath     string `toml:"dbpath"`
}

// maxConfigBytes bounds how much of the config file is read.
const maxConfigBytes = 64 << 10

// loadConfig reads the config file at path. With explicit unset, a missing
// file is not an error, since most users never create one.
func loadConfig(path string, explicit bool) (fileConfig, error) {
	var cfg fileConfig

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return cfg, nil
		}
		return cfg, fmt.Errorf("config: %w", err)
	}
	defer f.Close()

	// The file decides which socket the client trusts and where the daemon
	// keeps its database, so only its owner may be able to change it. A
	// symlink (say into a dotfiles repository) is fine: what is checked is the
	// file it leads to, through the descriptor actually read.
	fi, err := f.Stat()
	if err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return cfg, fmt.Errorf("config %s is not a regular file", path)
	}
	if err := checkConfigOwner(path, fi); err != nil {
		return cfg, err
	}

	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return cfg, fmt.Errorf("config: read %s: %w", path, err)
	}
	if len(data) > maxConfigBytes {
		return cfg, fmt.Errorf("config %s is larger than %d bytes", path, maxConfigBytes)
	}

	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	// A misspelt key would otherwise be silently ignored, leaving the client
	// looking in the wrong place with no clue why.
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return cfg, fmt.Errorf("config %s: unknown key(s) %s (want mode, group, fullaccess, socketpath, dbpath)",
			path, strings.Join(keys, ", "))
	}

	if cfg.SocketPath, err = configDir(path, "socketpath", cfg.SocketPath); err != nil {
		return cfg, err
	}
	if cfg.DBPath, err = configDir(path, "dbpath", cfg.DBPath); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// checkConfigOwner requires the config file to belong to us or root and to be
// writable by no one else.
func checkConfigOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("config %s: cannot determine owner on this platform", path)
	}
	if st.Uid != uint32(os.Getuid()) && st.Uid != 0 {
		return fmt.Errorf("config %s is owned by uid %d; it must be owned by you or root", path, st.Uid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("config %s has permissions %#o; must not be writable by group or others", path, perm)
	}
	return nil
}

// configDir expands a directory from the config file. It must be absolute or
// start with ~/, because a relative path would depend on the directory each
// command happened to be run from.
func configDir(cfgPath, key, v string) (string, error) {
	switch {
	case v == "":
		return "", nil
	case v == "~" || strings.HasPrefix(v, "~/"):
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config %s: %s: cannot determine home directory: %w", cfgPath, key, err)
		}
		return filepath.Join(home, strings.TrimPrefix(v, "~")), nil
	case filepath.IsAbs(v):
		return filepath.Clean(v), nil
	default:
		return "", fmt.Errorf("config %s: %s %q must be an absolute path or start with ~/", cfgPath, key, v)
	}
}

// configPath picks the config file: the -config value when given, otherwise
// the default location. An explicit empty -config disables the file.
func configPath(o globalOptions) (path string, explicit bool, err error) {
	if o.configSet {
		return o.config, true, nil
	}
	path, err = paths.DefaultConfigFile()
	return path, false, err
}
