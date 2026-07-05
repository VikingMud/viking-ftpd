package logging

import (
	"strings"
	"testing"
)

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want string
	}{
		{"plain", "hello", "hello"},
		{"space is quoted", "a b", `"a b"`},
		{"equals is quoted", "a=b", `"a=b"`},
		{"quote is escaped", `a"b`, `"a\"b"`},
		{"newline neutralized to space", "a\nb", `"a b"`},
		{"carriage return neutralized to space", "a\rb", `"a b"`},
		{"tab neutralized to space", "a\tb", `"a b"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatValue(tc.in); got != tc.want {
				t.Errorf("formatValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestFormatValueNoLineForging ensures a crafted value cannot inject a second
// log line via CR/LF.
func TestFormatValueNoLineForging(t *testing.T) {
	forged := "victim status=success\nop=fake user=attacker"
	got := formatValue(forged)
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("formatValue left a line break in output: %q", got)
	}
}
