package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadMasked(t *testing.T) {
	tests := []struct {
		name, input, want, echo string
	}{
		{"plain", "hunter2\r", "hunter2", "*******\r\n"},
		{"line feed ends input", "abc\n", "abc", "***\r\n"},
		{"backspace", "abx\x7fc\r", "abc", "***\b \b*\r\n"},
		{"ctrl-h backspace", "ab\x08c\r", "ac", "**\b \b*\r\n"},
		{"backspace on empty", "\x7fa\r", "a", "*\r\n"},
		{"multibyte rune is one star", "p€\r", "p€", "**\r\n"},
		{"backspace removes whole rune", "p€\x7fx\r", "px", "**\b \b*\r\n"},
		{"ctrl-u clears", "abc\x15xy\r", "xy", "***\b \b\b \b\b \b**\r\n"},
		{"arrow keys ignored", "a\x1b[Db\x1bOAc\r", "abc", "***\r\n"},
		{"alt key ignored", "a\x1bxb\r", "ab", "**\r\n"},
		{"tab ignored", "a\tb\r", "ab", "**\r\n"},
		{"long input grows buffer", strings.Repeat("z", 200) + "\r", strings.Repeat("z", 200), strings.Repeat("*", 200) + "\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var echo bytes.Buffer
			got, err := readMasked(strings.NewReader(tt.input), &echo)
			if err != nil {
				t.Fatalf("readMasked: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("input = %q, want %q", got, tt.want)
			}
			if echo.String() != tt.echo {
				t.Errorf("echo = %q, want %q", echo.String(), tt.echo)
			}
		})
	}
}

func TestReadMaskedCancels(t *testing.T) {
	for _, input := range []string{"abc\x03", "abc\x04", "abc" /* EOF */} {
		var echo bytes.Buffer
		got, err := readMasked(strings.NewReader(input), &echo)
		if !errors.Is(err, errEntryCancelled) {
			t.Errorf("readMasked(%q) error = %v, want errEntryCancelled", input, err)
		}
		if got != nil {
			t.Errorf("readMasked(%q) returned %q, want nil", input, got)
		}
	}
}
