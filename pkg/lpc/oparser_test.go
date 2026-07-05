package lpc

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Object Parsing Tests

func TestObjectParsing(t *testing.T) {
	t.Run("Basic Structure", func(t *testing.T) {
		tests := []struct {
			name     string
			input    string
			want     map[string]interface{}
			wantErr  bool
			strict   bool
			errCount int // Only relevant for non-strict mode
		}{
			{
				name:  "Simple Key Value",
				input: `name "Drake"`,
				want: map[string]interface{}{
					"name": "Drake",
				},
				strict: true,
			},
			{
				name: "Multiple Key Values",
				input: `name "Drake"
level 30
title "wizard"`,
				want: map[string]interface{}{
					"name":  "Drake",
					"level": 30,
					"title": "wizard",
				},
				strict: true,
			},
			{
				name: "Comments With Content",
				input: `# Header comment
name "Drake"
# Mid comment
level 30
# End comment`,
				want: map[string]interface{}{
					"name":  "Drake",
					"level": 30,
				},
			},
			{
				name: "Empty Lines Between Content",
				input: `name "Drake"

level 30

title "wizard"`,
				want: map[string]interface{}{
					"name":  "Drake",
					"level": 30,
					"title": "wizard",
				},
			},
			{
				name:    "Empty Input",
				input:   "",
				wantErr: true,
				strict:  true,
			},
			{
				name: "Invalid Line in Strict Mode",
				input: `name "Drake"
invalid line
level 30`,
				wantErr: true,
				strict:  true,
			},
			{
				name: "Skip Invalid Lines in Non-Strict Mode",
				input: `name "Drake"
invalid line
level 30
another bad line`,
				want: map[string]interface{}{
					"name":  "Drake",
					"level": 30,
				},
				strict:   false,
				errCount: 2,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := NewObjectParser(tt.strict)
				got, err := p.ParseObject(tt.input)

				if tt.strict {
					if (err != nil) != tt.wantErr {
						t.Errorf("ParseObject() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
				} else {
					if tt.errCount != len(got.Errors) {
						t.Errorf("ParseObject() error count = %v, want %v", len(got.Errors), tt.errCount)
						return
					}
				}

				if !tt.wantErr && !reflect.DeepEqual(got.Object, tt.want) {
					t.Errorf("ParseObject() got = %v, want %v", got.Object, tt.want)
				}
			})
		}
	})
}

// TestParseErrorReporting checks that a strict-mode failure returns a
// *ParseError located to the right line and column, and that its message
// includes both. This is the error contract callers rely on.
func TestParseErrorReporting(t *testing.T) {
	// Line 2 has an invalid value; the bad character '!' is at column 5
	// ("bad " is four bytes, so the value starts at 0-based pos 4).
	input := "good \"ok\"\nbad !value"

	_, err := NewObjectParser(true).ParseObject(input)
	if err == nil {
		t.Fatal("expected an error")
	}

	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if pe.Line != 2 {
		t.Errorf("Line = %d, want 2", pe.Line)
	}
	if pe.Column != 5 {
		t.Errorf("Column = %d, want 5", pe.Column)
	}
	if msg := pe.Error(); !strings.Contains(msg, "line 2, column 5") {
		t.Errorf("Error() = %q, want it to mention line 2, column 5", msg)
	}
}

// TestNonStrictCollectsErrorsAndSkips confirms non-strict mode keeps the good
// entries and records the bad lines rather than aborting.
func TestNonStrictCollectsErrorsAndSkips(t *testing.T) {
	input := "a 1\nbad !x\nb 2\nalso @bad\nc 3"

	res, err := NewObjectParser(false).ParseObject(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Object) != 3 {
		t.Errorf("kept %d entries, want 3 (a, b, c)", len(res.Object))
	}
	if len(res.Errors) != 2 {
		t.Errorf("collected %d errors, want 2", len(res.Errors))
	}
	for _, want := range []string{"a", "b", "c"} {
		if _, ok := res.Object[want]; !ok {
			t.Errorf("missing key %q", want)
		}
	}
}

// TestAllInvalidReturnsError confirms that an input with no parseable entries
// is an error with a nil result (result-xor-error contract).
func TestAllInvalidReturnsError(t *testing.T) {
	res, err := NewObjectParser(false).ParseObject("!bad\n@worse")
	if err == nil {
		t.Fatal("expected an error for wholly invalid input")
	}
	if res != nil {
		t.Errorf("expected nil result on error, got %+v", res)
	}
}

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

// TestCRLFLineHandling documents behavior on Windows line endings: the trailing
// '\r' becomes part of the line and makes the value invalid, but it must fail
// gracefully rather than panic or silently accept.
func TestCRLFLineHandling(t *testing.T) {
	// "a 1" is clean; "b 2\r" keeps a trailing carriage return that makes the
	// value invalid. CRLF input should fail gracefully per line, not panic.
	res, err := NewObjectParser(false).ParseObject("a 1\nb 2\r")
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if _, ok := res.Object["a"]; !ok || len(res.Object) != 1 {
		t.Errorf("expected only {a:1}, got %v", res.Object)
	}
	if len(res.Errors) != 1 {
		t.Errorf("expected 1 error for the CRLF line, got %d", len(res.Errors))
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

func TestLineParsing(t *testing.T) {
	t.Run("Basic Line Format", func(t *testing.T) {
		tests := []struct {
			name    string
			line    string
			wantKey string
			wantVal interface{}
			wantErr bool
			setup   func(t *testing.T)
		}{
			{
				name:    "Simple String Value",
				line:    `name "Drake"`,
				wantKey: "name",
				wantVal: "Drake",
			},
			{
				name:    "Simple Integer Value",
				line:    "age 25",
				wantKey: "age",
				wantVal: 25,
			},
			{
				name:    "Empty Line",
				line:    "",
				wantKey: "",
				wantVal: nil,
				wantErr: false,
			},
			{
				name:    "Missing Value",
				line:    "name",
				wantErr: true,
			},
			{
				name:    "Missing Space",
				line:    "name\"Drake\"",
				wantErr: true,
			},
			{
				name:    "Multiple Spaces",
				line:    "name  \"Drake\"",
				wantErr: true,
			},
			{
				name:    "Invalid Key Format",
				line:    "user name \"Drake\"",
				wantErr: true,
			},
			{
				name:    "Tab Separator",
				line:    "name\t\"Drake\"",
				wantErr: true,
			},
			{
				name:    "Only Tab",
				line:    "\t",
				wantErr: true,
			},
			{
				name:    "Only Spaces",
				line:    "   ",
				wantErr: true,
			},
			{
				name:    "Mixed Whitespace",
				line:    " \t  ",
				wantErr: true,
			},
			{
				name:    "Leading Whitespace",
				line:    " name \"Drake\"",
				wantErr: true,
			},
			{
				name:    "Trailing Whitespace",
				line:    "name \"Drake\" ",
				wantErr: true,
			},
			{
				name:    "Multiple Spaces Between Key Value",
				line:    "name    \"Drake\"",
				wantErr: true,
			},
			{
				name:    "Tab Between Key Value",
				line:    "name\t\"Drake\"",
				wantErr: true,
			},
			{
				name:    "Leading Space In Comment",
				line:    "   # This is a comment",
				wantErr: true,
			},
			{
				name:    "Invalid Number Format",
				line:    "12.34.56",
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.setup != nil {
					tt.setup(t)
				}
				lp := newLineParser(tt.line)
				key, val, err := lp.parseLine()
				if (err != nil) != tt.wantErr {
					t.Errorf("ParseLine() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !tt.wantErr {
					if key != tt.wantKey {
						t.Errorf("ParseLine() key = %v, want %v", key, tt.wantKey)
					}
					if !reflect.DeepEqual(val, tt.wantVal) {
						t.Errorf("ParseLine() val = %v, want %v", val, tt.wantVal)
					}
				}
			})
		}
	})

}

func TestValueParsing(t *testing.T) {
	t.Run("Strings", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			want    string
			wantErr bool
		}{
			// Basic strings
			{
				name:  "Empty String",
				input: `""`,
				want:  "",
			},
			{
				name:  "Simple String",
				input: `"hello"`,
				want:  "hello",
			},
			// Control characters
			{
				name:  "Newline Escape",
				input: `"line1\nline2"`,
				want:  "line1\nline2",
			},
			{
				name:  "Tab Escape",
				input: `"col1\tcol2"`,
				want:  "col1\tcol2",
			},
			{
				name:  "Carriage Return",
				input: `"return\rhere"`,
				want:  "return\rhere",
			},
			{
				name:  "Form Feed",
				input: `"form\ffeed"`,
				want:  "form\ffeed",
			},
			{
				name:  "Vertical Tab",
				input: `"vert\vtab"`,
				want:  "vert\vtab",
			},
			// Special characters
			{
				name:  "Double Quote Escape",
				input: `"quote\"here"`,
				want:  `quote"here`,
			},
			{
				name:  "Backslash Escape",
				input: `"C:\\path\\to\\file"`,
				want:  `C:\path\to\file`,
			},
			{
				name:  "Bell Character",
				input: `"alert\a"`,
				want:  "alert\a",
			},
			{
				name:  "Backspace",
				input: `"back\bspace"`,
				want:  "back\bspace",
			},
			{
				name:  "Null Character",
				input: `"hello\0world"`,
				want:  "hello\x00world",
			},
			// Complex cases
			{
				name:  "Multiple Escapes",
				input: `"line1\nline2\tcolumn2\nline3"`,
				want:  "line1\nline2\tcolumn2\nline3",
			},
			{
				name:  "Unknown Escape",
				input: `"hello\zworld"`,
				want:  "hellozworld", // DGD behavior: unknown escapes are taken literally
			},
			// Error cases
			{
				name:    "Unterminated String",
				input:   `"hello`,
				wantErr: true,
			},
			{
				name:    "Unterminated Escape",
				input:   `"hello\`,
				wantErr: true,
			},
			{
				name:    "Newline In String",
				input:   "\"hello\nworld\"",
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				lp := newLineParser(tt.input)
				got, err := lp.parseString()
				if (err != nil) != tt.wantErr {
					t.Errorf("parseString() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !tt.wantErr && got != tt.want {
					t.Errorf("parseString() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("Numbers", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			want    interface{}
			wantErr bool
		}{
			// Integers
			{
				name:  "Zero",
				input: "0",
				want:  0,
			},
			{
				name:  "Positive Integer",
				input: "42",
				want:  42,
			},
			{
				name:  "Negative Integer",
				input: "-42",
				want:  -42,
			},
			// Floats
			{
				name:  "Simple Float",
				input: "3.14",
				want:  3.14,
			},
			{
				name:  "Negative Float",
				input: "-3.14",
				want:  -3.14,
			},
			// Hex notation
			{
				name:  "Float With Hex",
				input: "3.14=0x4048f5c3",
				want:  3.14,
			},
			{
				name:  "Zero With Hex",
				input: "0=0000000000000000",
				want:  0.0,
			},
			{
				name:  "Negative With Hex",
				input: "-1=bff0000000000000",
				want:  -1.0,
			},
			{
				name:    "Invalid Hex Format",
				input:   "1.0=xyz",
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				lp := newLineParser(tt.input)
				got, err := lp.parseNumber()
				t.Logf("parseNumber() returned value: %v, error: %v", got, err)
				if (err != nil) != tt.wantErr {
					t.Errorf("parseNumber() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
					t.Errorf("parseNumber() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("Nil Values", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			want    interface{}
			wantErr bool
		}{
			{
				name:  "Nil Value",
				input: "nil",
				want:  nil,
			},
			{
				name:    "Invalid Nil Value",
				input:   "nill",
				wantErr: true,
			},
			{
				name:    "Invalid Nil Case",
				input:   "NIL",
				wantErr: true,
			},
			{
				name:    "Missing Nil",
				input:   "",
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				lp := newLineParser(tt.input)
				got, err := lp.parseValue()
				if (err != nil) != tt.wantErr {
					t.Errorf("parseValue() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
					t.Errorf("parseValue() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("Arrays", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			want    []interface{}
			wantErr bool
		}{
			// Basic arrays
			{
				name:  "Empty Array",
				input: "({0|})",
				want:  []interface{}{},
			},
			{
				name:  "Empty Array With Comma",
				input: "({0|,})",
				want:  []interface{}{},
			},
			{
				name:  "Simple Array",
				input: `({3|"a",1,2})`,
				want:  []interface{}{"a", 1, 2},
			},
			{
				name:  "Array With Trailing Comma",
				input: `({2|1,2,})`,
				want:  []interface{}{1, 2},
			},
			// Complex arrays
			{
				name:  "Mixed Type Values",
				input: `({4|"hello",42,3.14,nil})`,
				want:  []interface{}{"hello", 42, 3.14, nil},
			},
			{
				name:  "Nested Array",
				input: `({2|({2|1,2}),({2|3,4})})`,
				want:  []interface{}{[]interface{}{1, 2}, []interface{}{3, 4}},
			},
			{
				name:  "Array With Nil",
				input: "({1|nil})",
				want:  []interface{}{nil},
			},
			// Error cases
			{
				name:    "Too Many Elements",
				input:   "({1|1,2})",
				wantErr: true,
			},
			{
				name:    "Too Few Elements",
				input:   "({2|1})",
				wantErr: true,
			},
			{
				name:    "Invalid Format",
				input:   "({not an array})",
				wantErr: true,
			},
			{
				name:    "Malformed Start",
				input:   "{1|2})",
				wantErr: true,
			},
			{
				name:    "Malformed End",
				input:   "({1|2}",
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				lp := newLineParser(tt.input)
				got, err := lp.parseArray()
				if (err != nil) != tt.wantErr {
					t.Errorf("parseArray() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
					t.Errorf("parseArray() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("Maps", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			want    map[string]interface{}
			wantErr bool
		}{
			// Basic maps
			{
				name:  "Empty Map",
				input: "([0|])",
				want:  map[string]interface{}{},
			},
			{
				name:  "Simple Map",
				input: `([2|"a":1,"b":2])`,
				want: map[string]interface{}{
					"a": 1,
					"b": 2,
				},
			},
			{
				name:  "Map With Trailing Comma",
				input: `([2|"a":1,"b":2,])`,
				want: map[string]interface{}{
					"a": 1,
					"b": 2,
				},
			},
			// Complex maps
			{
				name:  "Map With Mixed Values",
				input: `([3|"a":"hello","b":42,"c":3.14])`,
				want: map[string]interface{}{
					"a": "hello",
					"b": 42,
					"c": 3.14,
				},
			},
			{
				name:  "Empty Array Key",
				input: `([1|({0|}):42])`,
				want:  map[string]interface{}{}, // Array key is skipped
			},
			{
				name:  "Array Key With String Value",
				input: `([1|({2|1,2}):"hello"])`,
				want:  map[string]interface{}{}, // Array key is skipped
			},
			{
				name:  "Map Key With Number Value",
				input: `([1|([1|"x":1]):42])`,
				want:  map[string]interface{}{}, // Map key is skipped
			},
			{
				name:  "Mixed Key Types",
				input: `([3|({2|1,2}):3,"a":1,([1|"x":1]):2])`,
				want: map[string]interface{}{
					"a": 1, // Only primitive key is kept
				},
			},
			// Error cases
			{
				name:    "Missing Colon",
				input:   `([1|"a" 1])`,
				wantErr: true,
			},
			{
				name:    "Size Mismatch",
				input:   `([2|"a":1])`,
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				lp := newLineParser(tt.input)
				got, err := lp.parseMap()
				if (err != nil) != tt.wantErr {
					t.Errorf("parseMap() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
					t.Errorf("parseMap() = %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("Nested Structures", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			want    interface{}
			wantErr bool
		}{
			{
				name:  "Array in Map",
				input: `([1|"arr":({3|1,2,3})])`,
				want: map[string]interface{}{
					"arr": []interface{}{1, 2, 3},
				},
			},
			{
				name:  "Map in Array",
				input: `({1|([1|"key":"value"])})`,
				want: []interface{}{
					map[string]interface{}{
						"key": "value",
					},
				},
			},
			{
				name:  "Array in Map in Array",
				input: `({1|([1|"arr":({2|1,2})])})`,
				want: []interface{}{
					map[string]interface{}{
						"arr": []interface{}{1, 2},
					},
				},
			},
			{
				name:    "Invalid Nesting",
				input:   `([1|"arr":({2|1,([1|"x":1})])`,
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := newLineParser(tt.input)
				got, err := p.parseValue()
				if (err != nil) != tt.wantErr {
					t.Errorf("parseValue() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
					t.Errorf("parseValue() = %v, want %v", got, tt.want)
				}
			})
		}
	})
}

// TestIntegerOverflow makes sure an out-of-range integer is a graceful error,
// not a panic.
func TestIntegerOverflow(t *testing.T) {
	res, err := NewObjectParser(false).ParseObject("ok 1\nn 999999999999999999999999999999")
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected 1 collected error, got %d", len(res.Errors))
	}
	if _, ok := res.Object["n"]; ok {
		t.Error("overflowing integer should not have been stored")
	}
}

// TestComplexKeysSkipped confirms the whole-object path where a mapping has an
// array/map key: the entry is dropped but still counted toward the size.
func TestComplexKeysSkipped(t *testing.T) {
	// size 2: one array-keyed entry (skipped) and one normal entry (kept).
	res, err := NewObjectParser(true).ParseObject(`m ([2|({1|1}):5,"keep":7])`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := res.Object["m"].(map[string]interface{})
	if !ok {
		t.Fatalf("m is not a map: %T", res.Object["m"])
	}
	if len(m) != 1 || m["keep"] != 7 {
		t.Errorf("map = %v, want only {keep:7}", m)
	}
}

// TestDeeplyNested exercises recursion depth without a stack helper.
func TestDeeplyNested(t *testing.T) {
	const depth = 200
	in := "x " + strings.Repeat("({1|", depth) + "1" + strings.Repeat("})", depth)

	res, err := NewObjectParser(true).ParseObject(in)
	if err != nil {
		t.Fatalf("unexpected error at depth %d: %v", depth, err)
	}
	// Walk back down and confirm the innermost value survived.
	cur := res.Object["x"]
	for i := 0; i < depth; i++ {
		arr, ok := cur.([]interface{})
		if !ok || len(arr) != 1 {
			t.Fatalf("level %d is not a 1-element array: %T", i, cur)
		}
		cur = arr[0]
	}
	if cur != 1 {
		t.Errorf("innermost value = %v, want 1", cur)
	}
}

// Real World File Parsing Tests
func TestRealWorldFileParsing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real-world file tests in short mode")
	}

	// Print current working directory for debugging
	cwd, _ := os.Getwd()
	t.Logf("Current working directory: %s", cwd)

	// Test character files
	characterPath := "../../resources/characters"
	t.Logf("Looking for characters in: %s", characterPath)

	// Skip if character directory doesn't exist
	if _, err := os.Stat(characterPath); os.IsNotExist(err) {
		t.Skip("Skipping real-world file tests: character directory not found")
	}

	err := filepath.Walk(characterPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".o") {
			t.Run(path, func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("Failed to read file %s: %v", path, err)
				}

				p := NewObjectParser(true)
				_, err = p.ParseObject(string(data))
				if err != nil {
					t.Errorf("Failed to parse %s: %v", path, err)
				}
			})
		}
		return nil
	})
	if err != nil {
		t.Errorf("Failed to walk character files: %v", err)
	}
}
