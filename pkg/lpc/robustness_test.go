package lpc

import "testing"

// TestParseObjectNoPanicOnTruncatedInput covers malformed/truncated objects
// that must produce a parse error rather than crashing. The "nil" cases in
// particular previously panicked in match() by slicing past the end of the
// line while trying to match the literal "nil".
func TestParseObjectNoPanicOnTruncatedInput(t *testing.T) {
	inputs := []string{
		"x n",                    // value truncated to "n"
		"x ni",                   // value truncated to "ni"
		"n",                      // no key/value, starts with n
		"m ([1|\"a\":n",          // truncated nil inside a mapping
		"a ({1|n",                // truncated nil inside an array
		"m ([2|\"a\":1,\"b\":ni", // truncated nil as a later map value
		"x (",                    // truncated container
		"x ({",                   // truncated array open
		"x ([",                   // truncated map open
		"x \"unterminated",       // unterminated string
		"m ([1|\"k\":({2|1,2",    // truncated nested array
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			// The assertion is simply that neither parser mode panics; a panic
			// here would fail the subtest.
			_, _ = NewObjectParser(false).ParseObject(in)
			_, _ = NewObjectParser(true).ParseObject(in)
		})
	}
}

// TestParseObjectValidNilStillWorks guards against the bounds fix breaking the
// normal nil path.
func TestParseObjectValidNilStillWorks(t *testing.T) {
	res, err := NewObjectParser(true).ParseObject("value nil")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v, ok := res.Object["value"]
	if !ok || v != nil {
		t.Fatalf("expected value=nil, got %#v (present=%v)", v, ok)
	}
}
