package lpc

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ParsingContext holds all shared state during LPC object parsing.
// This includes reference tracking and error context information.
type ParsingContext struct {
	arrayRefs []interface{} // parsed arrays for reference resolution
	mapRefs   []interface{} // parsed mappings for reference resolution
	filename  string        // filename for error messages (optional)
	lineNum   int           // current line number for error messages
	strict    bool          // strict parsing mode
}

// ObjectParser holds parsing configuration for LPC object format.
// The format is used to store and restore object state in DGD.
type ObjectParser struct {
	strict bool
}

// NewObjectParser creates a new parser with the given options.
// In strict mode, any parsing error will stop the entire process.
// In non-strict mode, errors are collected and parsing continues.
func NewObjectParser(strict bool) *ObjectParser {
	return &ObjectParser{
		strict: strict,
	}
}

// ParseError represents an error that occurred while parsing a specific line
type ParseError struct {
	Line     int   // The line number where the error occurred
	Position int   // Position within the line where the error occurred
	Err      error // The specific error encountered
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("Format error at line %d: %v", e.Line, e.Err)
}

// ParseResult contains both the parsed object and any errors encountered.
// In strict mode, Errors will be empty as any error stops parsing.
// In non-strict mode, Errors may contain multiple parsing errors.
type ParseResult struct {
	Object map[string]interface{} // Key-value pairs from the object
	Errors []*ParseError          // Any errors encountered during parsing
}

// LineParser handles parsing of individual lines in LPC object format.
// The format requires:
// - No leading or trailing whitespace
// - Exactly one space between key and value
// - No tabs
// - Keys must be valid identifiers
type LineParser struct {
	s   string // input string
	pos int    // current position in string
	w   int    // width of last rune read
}

// NewLineParser creates a new parser for a single line
func NewLineParser(line string) *LineParser {
	return &LineParser{
		s:   line,
		pos: 0,
		w:   0,
	}
}


// ParseObject parses an LPC object from the input string.
// The input should consist of key-value pairs, one per line.
// Empty lines and lines starting with # are ignored.
// Returns error if input is empty or invalid.
func (p *ObjectParser) ParseObject(input string) (*ParseResult, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("input string is empty")
	}

	result := &ParseResult{
		Object: make(map[string]interface{}),
		Errors: make([]*ParseError, 0),
	}

	// Create parsing context to track references and state
	ctx := &ParsingContext{
		arrayRefs: make([]interface{}, 0),
		mapRefs:   make([]interface{}, 0),
		strict:    p.strict,
	}

	lines := strings.Split(input, "\n")
	startPos := 0

	for lineNum, line := range lines {
		// Skip empty lines and comments
		if len(line) == 0 || line[0] == '#' {
			startPos += len(line) + 1 // +1 for newline
			continue
		}

		// Update context with current line info
		ctx.lineNum = lineNum + 1

		// Parse key and value
		lp := NewLineParser(line)
		key, value, err := lp.ParseLine(ctx)
		if err != nil {
			parseErr := &ParseError{
				Line:     lineNum + 1,
				Position: startPos + lp.pos,
				Err:      err,
			}

			if p.strict {
				return nil, parseErr
			}
			result.Errors = append(result.Errors, parseErr)
		} else {
			result.Object[key] = value
		}

		startPos += len(line) + 1 // +1 for newline
	}

	if len(result.Object) == 0 && len(result.Errors) > 0 {
		return result, fmt.Errorf("no valid entries found")
	}

	return result, nil
}

// ParseLine parses a single line of LPC object format, returning the key and value.
// Format rules:
// - Lines starting with # are treated as comments and skipped
// - Empty lines are skipped
// - No leading or trailing whitespace allowed
// - Exactly one space between key and value
// - No tabs allowed
// - Line must end with newline or EOF
// The ctx parameter can be nil for simple parsing, or provided to enable reference resolution.
func (p *LineParser) ParseLine(ctx *ParsingContext) (string, interface{}, error) {
	// Skip comment lines
	if p.peek(0) == '#' {
		return "", nil, nil
	}

	// Skip empty lines
	if p.peek(0) == '\n' || p.peek(0) == 0 {
		return "", nil, nil
	}

	// Leading whitespace is not allowed
	if p.peek(0) == ' ' || p.peek(0) == '\t' {
		return "", nil, fmt.Errorf("leading whitespace not allowed at position %d", p.pos)
	}

	// Parse identifier - must start with letter or underscore
	key, err := p.parseIdentifier()
	if err != nil {
		return "", nil, err
	}

	// Check for exactly one space after key
	if p.peek(0) != ' ' {
		return "", nil, fmt.Errorf("expected single space after key at position %d", p.pos)
	}
	p.next() // consume the single space
	if p.peek(0) == ' ' || p.peek(0) == '\t' {
		return "", nil, fmt.Errorf("multiple spaces or tabs not allowed at position %d", p.pos)
	}

	value, err := p.parseValue(ctx)
	if err != nil {
		return "", nil, err
	}

	// Check for trailing whitespace
	r := p.peek(0)
	if r == ' ' || r == '\t' {
		return "", nil, fmt.Errorf("trailing whitespace not allowed at position %d", p.pos)
	}
	if r != '\n' && r != 0 {
		return "", nil, fmt.Errorf("expected newline or end of file at position %d", p.pos)
	}

	return key, value, nil
}

// parseValue parses any valid value type.
// Value types can be:
// - Strings (double-quoted)
// - Integers
// - Floats (with optional hex notation)
// - Arrays
// - Maps
// - nil
// - Array references (#n)
// - Mapping references (@n)
func (p *LineParser) parseValue(ctx *ParsingContext) (interface{}, error) {
	p.skipSpaces()

	r := p.peek(0)
	if r == '"' {
		return p.parseString()
	} else if unicode.IsDigit(r) || r == '-' {
		return p.parseNumber()
	} else if r == '(' {
		// Could be array or map
		if p.peek(1) == '{' {
			array, err := p.parseArray(ctx)
			if err == nil && ctx != nil {
				ctx.arrayRefs = append(ctx.arrayRefs, array)
			}
			return array, err
		} else if p.peek(1) == '[' {
			mapping, err := p.parseMap(ctx)
			if err == nil && ctx != nil {
				ctx.mapRefs = append(ctx.mapRefs, mapping)
			}
			return mapping, err
		}
		return nil, fmt.Errorf("invalid value starting with '(' at position %d", p.pos)
	} else if r == 'n' {
		// Try parsing nil
		pos := p.pos
		if p.match("nil") && p.isValidTerminator(p.peek(0)) {
			return nil, nil
		}
		p.pos = pos
		return nil, fmt.Errorf("invalid nil value at position %d", p.pos)
	} else if r == '#' {
		// Array reference
		return p.parseArrayReference(ctx)
	} else if r == '@' {
		// Mapping reference
		return p.parseMappingReference(ctx)
	}

	return nil, fmt.Errorf("invalid value starting with '%c' at position %d", r, p.pos)
}


func (p *LineParser) isValidTerminator(r rune) bool {
	return r == ',' || r == ':' || r == ']' || r == '}' || r == ')' || r == '\n' || r == 0
}

// parseArrayReference parses an array reference (#n).
// Returns the referenced array from the shared arrayRefs list.
func (p *LineParser) parseArrayReference(ctx *ParsingContext) (interface{}, error) {
	if ctx == nil {
		return nil, fmt.Errorf("array references not supported without parsing context")
	}

	if !p.expect('#') {
		return nil, fmt.Errorf("expected '#' at position %d", p.pos)
	}

	index, err := p.parseInt()
	if err != nil {
		return nil, fmt.Errorf("invalid array reference index: %v", err)
	}

	if index < 0 || index >= len(ctx.arrayRefs) {
		return nil, fmt.Errorf("array reference #%d out of bounds (have %d arrays)", index, len(ctx.arrayRefs))
	}

	return ctx.arrayRefs[index], nil
}

// parseMappingReference parses a mapping reference (@n).
// Returns the referenced mapping from the shared mapRefs list.
func (p *LineParser) parseMappingReference(ctx *ParsingContext) (interface{}, error) {
	if ctx == nil {
		return nil, fmt.Errorf("mapping references not supported without parsing context")
	}

	if !p.expect('@') {
		return nil, fmt.Errorf("expected '@' at position %d", p.pos)
	}

	index, err := p.parseInt()
	if err != nil {
		return nil, fmt.Errorf("invalid mapping reference index: %v", err)
	}

	if index < 0 || index >= len(ctx.mapRefs) {
		return nil, fmt.Errorf("mapping reference @%d out of bounds (have %d mappings)", index, len(ctx.mapRefs))
	}

	return ctx.mapRefs[index], nil
}

// parseArray parses an array value.
// Format: ({size|val1,val2,...})
// - Size must match the number of elements
// - Elements are comma-separated with no trailing comma
// - Arrays can be nested
func (p *LineParser) parseArray(ctx *ParsingContext) ([]interface{}, error) {
	if !p.match("({") {
		return nil, fmt.Errorf("error in array: expected '({' at position %d", p.pos)
	}

	// Parse size
	size, err := p.parseInt()
	if err != nil {
		return nil, fmt.Errorf("error in array: invalid size at position %d: %v", p.pos, err)
	}

	if !p.expect('|') {
		return nil, fmt.Errorf("error in array: expected '|' after size at position %d", p.pos)
	}

	// Parse elements
	elements := make([]interface{}, 0)

	// Handle empty array cases (with or without trailing comma)
	p.skipSpaces()
	if p.peek(0) == '}' && p.peek(1) == ')' {
		p.pos += 2
		if size != 0 {
			return nil, fmt.Errorf("error in array: empty array but size is %d", size)
		}
		return elements, nil
	}
	if p.peek(0) == ',' && p.peek(1) == '}' && p.peek(2) == ')' {
		p.pos += 3
		if size != 0 {
			return nil, fmt.Errorf("error in array: empty array but size is %d", size)
		}
		return elements, nil
	}

	// Parse elements
	for {
		// Parse element
		element, err := p.parseValue(ctx)
		if err != nil {
			return nil, fmt.Errorf("error in array: %v", err)
		}
		elements = append(elements, element)

		p.skipSpaces()
		if p.peek(0) == ',' {
			p.pos++ // consume comma
			p.skipSpaces()
			// Check for trailing comma
			if p.peek(0) == '}' && p.peek(1) == ')' {
				p.pos += 2
				break
			}
			continue
		} else if p.peek(0) == '}' && p.peek(1) == ')' {
			p.pos += 2
			break
		} else {
			return nil, fmt.Errorf("error in array: expected ',' or '})' at position %d", p.pos)
		}
	}

	// Verify size matches number of elements
	if len(elements) > size {
		return nil, fmt.Errorf("error in array: too many elements, expected %d", size)
	} else if len(elements) < size {
		return nil, fmt.Errorf("error in array: too few elements, expected %d", size)
	}

	return elements, nil
}


// parseMap parses a mapping value.
// Format: ([size|key1:val1,key2:val2,...])
// - Size must match the number of entries
// - Entries are comma-separated with no trailing comma
// - Keys can be any valid value type
// - Values can be any valid value type
// - Mappings can be nested
func (p *LineParser) parseMap(ctx *ParsingContext) (map[string]interface{}, error) {
	if !p.match("([") {
		return nil, fmt.Errorf("error in map: expected '([' at position %d", p.pos)
	}

	// Parse size
	size, err := p.parseInt()
	if err != nil {
		return nil, fmt.Errorf("error in map: invalid size at position %d: %v", p.pos, err)
	}

	if !p.expect('|') {
		return nil, fmt.Errorf("error in map: expected '|' after size at position %d", p.pos)
	}

	// Parse entries
	result := make(map[string]interface{})
	totalEntries := 0
	validEntries := 0

	// Handle empty map
	p.skipSpaces()
	if p.peek(0) == ']' && p.peek(1) == ')' {
		p.pos += 2
		if size != 0 {
			return nil, fmt.Errorf("error in map: empty map but size is %d", size)
		}
		return result, nil
	}

	for {
		// Parse key:value pair
		key, value, skipped, err := p.parseMapEntry(ctx)
		if err != nil {
			return nil, err
		}

		totalEntries++
		if !skipped {
			result[key] = value
			validEntries++
		}

		p.skipSpaces()
		if p.peek(0) == ',' {
			p.pos++ // consume comma
			p.skipSpaces()
			if p.peek(0) == ']' && p.peek(1) == ')' {
				p.pos += 2
				break
			}
			continue
		} else if p.peek(0) == ']' && p.peek(1) == ')' {
			p.pos += 2
			break
		} else {
			return nil, fmt.Errorf("error in map: expected ',' or '])' at position %d", p.pos)
		}
	}

	// Verify size matches total number of entries (including skipped ones)
	if totalEntries > size {
		return nil, fmt.Errorf("error in map: too many entries, expected %d", size)
	} else if totalEntries < size {
		return nil, fmt.Errorf("error in map: too few entries, expected %d", size)
	}

	// If we have no valid entries but size > 0, that means all entries were skipped
	if validEntries == 0 && size > 0 {
		return make(map[string]interface{}), nil
	}

	return result, nil
}

var escapeSequences = map[rune]rune{
	'0':  0,
	'a':  '\a',
	'b':  '\b',
	't':  '\t',
	'n':  '\n',
	'v':  '\v',
	'f':  '\f',
	'r':  '\r',
	'"':  '"',
	'\\': '\\',
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// ParseMapEntry parses a single key:value pair in a mapping.
// While the LPC Object Format specification allows any valid value type as keys,
// this implementation only supports primitive types (strings, numbers, and nil) as keys.
// Complex types (arrays and maps) as keys will be skipped during parsing.
// Keys can be:
// - Strings
// - Integers
// - Floats
// - nil
// Values can be any valid value type.
func (p *LineParser) parseMapEntry(ctx *ParsingContext) (string, interface{}, bool, error) {
	p.skipSpaces()

	// Parse key - can be any valid value type
	keyValue, err := p.parseValue(ctx)
	if err != nil {
		return "", nil, false, fmt.Errorf("error in map entry: invalid key at position %d: %v", p.pos, err)
	}

	// Convert key to string representation
	var key string
	switch v := keyValue.(type) {
	case string:
		key = v
	case int:
		key = strconv.Itoa(v)
	case float64:
		key = strconv.FormatFloat(v, 'f', -1, 64)
	case []interface{}, map[string]interface{}:
		// Skip array and map keys but count them
		p.skipSpaces()
		if p.peek(0) == ':' {
			p.next() // skip :
			// Parse and discard the value
			if _, err := p.parseValue(ctx); err != nil {
				return "", nil, false, err
			}
		}
		return "", nil, true, nil
	case nil:
		key = "nil"
	default:
		return "", nil, false, fmt.Errorf("error in map entry: unsupported key type %T at position %d", keyValue, p.pos)
	}

	p.skipSpaces()
	if !p.expect(':') {
		return "", nil, false, fmt.Errorf("error in map entry: expected ':' after key at position %d", p.pos)
	}

	// Parse value
	value, err := p.parseValue(ctx)
	if err != nil {
		return "", nil, false, err
	}

	return key, value, false, nil
}

// ParseNumber parses either an integer or float value.
// Floats may include hex notation after = sign.
// Format: [-]digits[.digits][=hexdigits]
func (p *LineParser) parseNumber() (interface{}, error) {
	// Look ahead to see if this is a float
	offset := 0
	if p.peek(offset) == '-' {
		offset++
	}
	// Skip digits
	for unicode.IsDigit(p.peek(offset)) {
		offset++
	}
	// Check for decimal point or hex notation
	if p.peek(offset) == '.' || p.peek(offset) == '=' {
		return p.parseFloat()
	}
	return p.parseInt()
}

// ParseInt parses an integer from the input string
func (p *LineParser) parseInt() (int, error) {
	start := p.pos
	if p.peek(0) == '-' {
		p.next()
	}
	for unicode.IsDigit(p.peek(0)) {
		p.next()
	}

	result, err := strconv.Atoi(p.s[start:p.pos])
	if err != nil {
		return 0, fmt.Errorf("error in integer: invalid number at position %d", p.pos)
	}
	return result, nil
}

// next returns the next rune and advances the position
func (p *LineParser) next() rune {
	if p.pos >= len(p.s) {
		p.w = 0
		return 0
	}
	r, w := utf8.DecodeRuneInString(p.s[p.pos:])
	p.pos += w
	p.w = w
	return r
}

// Peek returns the rune at the current position without advancing the position
func (p *LineParser) peek(n int) rune {
	if p.pos+n >= len(p.s) {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(p.s[p.pos+n:])
	return r
}

// Expect checks if the next rune matches the given rune and advances the position if it does
func (p *LineParser) expect(r rune) bool {
	if p.next() == r {
		return true
	}
	p.pos -= p.w
	return false
}

// SkipSpaces skips any whitespace characters
func (p *LineParser) skipSpaces() {
	for {
		r := p.peek(0)
		if r != ' ' && r != '\t' {
			break
		}
		p.next()
	}
}

// match checks if the next runes match the given string and advances the position if they do
func (p *LineParser) match(s string) bool {
	if p.s[p.pos:p.pos+len(s)] == s {
		p.pos += len(s)
		return true
	}
	return false
}

// parseFloat parses a float value, optionally with hex notation.
// Format: [-]digits[.digits][=hexdigits]
// The hex part represents the IEEE 754 bits of the float.
func (p *LineParser) parseFloat() (float64, error) {
	start := p.pos

	if p.peek(0) == '-' {
		p.next()
	}

	// Must have at least one digit
	if !unicode.IsDigit(p.peek(0)) {
		return 0, fmt.Errorf("float value must start with a digit at position %d", p.pos)
	}

	// Parse integer part
	for unicode.IsDigit(p.peek(0)) {
		p.next()
	}

	// Parse optional decimal part
	if p.peek(0) == '.' {
		p.next()
		// Must have at least one digit after the decimal point
		if !unicode.IsDigit(p.peek(0)) {
			return 0, fmt.Errorf("float value must have digits after decimal point at position %d", p.pos)
		}
		for unicode.IsDigit(p.peek(0)) {
			p.next()
		}
	}

	// If no decimal point or hex notation, it must have hex notation
	if p.peek(0) != '=' && !strings.Contains(p.s[start:p.pos], ".") {
		return 0, fmt.Errorf("float value must contain a decimal point or hex representation at position %d", p.pos)
	}

	floatStr := p.s[start:p.pos]
	result, err := strconv.ParseFloat(floatStr, 64)
	if err != nil {
		return 0, fmt.Errorf("error in float: invalid number at position %d", p.pos)
	}

	// Parse optional hex part
	if p.peek(0) == '=' {
		p.next() // skip =
		if !isHexDigit(p.peek(0)) {
			return 0, fmt.Errorf("invalid hex digits after = at position %d", p.pos)
		}
		for isHexDigit(p.peek(0)) {
			p.next()
		}
	}

	return result, nil
}

// ParseString parses a double-quoted string with escape sequences.
// Supported escape sequences:
// - \0  - null character
// - \a  - bell (BEL)
// - \b  - backspace
// - \t  - tab
// - \n  - newline
// - \v  - vertical tab
// - \f  - form feed
// - \r  - carriage return
// - \"  - double quote
// - \\  - backslash
// Any other character after backslash is taken literally.
// Newlines are not allowed in strings.
func (p *LineParser) parseString() (string, error) {
	if !p.match("\"") {
		return "", fmt.Errorf("expected '\"' at position %d", p.pos)
	}

	var b strings.Builder
	for p.pos < len(p.s) {
		r := p.next()
		if r == '"' {
			return b.String(), nil
		}
		if r == '\\' {
			if p.pos >= len(p.s) {
				return "", fmt.Errorf("unterminated string at position %d", p.pos)
			}
			r = p.next()
			if escaped, ok := escapeSequences[r]; ok {
				b.WriteRune(escaped)
			} else {
				b.WriteRune(r) // Unknown escape sequences are taken literally
			}
			continue
		}
		if r == '\n' {
			return "", fmt.Errorf("newline in string at position %d", p.pos)
		}
		b.WriteRune(r)
	}
	return "", fmt.Errorf("unterminated string at position %d", p.pos)
}

// ParseIdentifier parses an identifier from the input string.
// An identifier consists of letters, digits, and underscores.
// The first character must be a letter.
func (p *LineParser) parseIdentifier() (string, error) {
	start := p.pos
	r := p.next()
	if !unicode.IsLetter(r) {
		return "", fmt.Errorf("identifier must start with a letter at position %d", p.pos)
	}
	for r = p.next(); unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'; r = p.next() {
		if r == 0 {
			return "", fmt.Errorf("unexpected end of input while parsing identifier at position %d", p.pos)
		}
	}
	p.pos -= p.w // back up to last character of identifier
	return p.s[start:p.pos], nil
}
