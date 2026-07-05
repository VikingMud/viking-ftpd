// Package lpc parses the LPC serialized object format used by DGD/LPMuds to
// store object state (e.g. character files and the MUD's access map).
//
// A file is a sequence of "key value" lines. Values are strings, integers,
// floats, arrays ({size|...}), mappings ([size|k:v,...]), or nil. The parser is
// a hand-written recursive descent parser over a byte cursor: the format is
// entirely ASCII-delimited, and UTF-8 payload inside string values is preserved
// byte for byte.
package lpc

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ObjectParser parses whole objects. In strict mode the first error aborts the
// parse; otherwise per-line errors are collected and parsing continues.
type ObjectParser struct {
	strict bool
}

// NewObjectParser creates a parser. See ObjectParser for the strict flag.
func NewObjectParser(strict bool) *ObjectParser {
	return &ObjectParser{strict: strict}
}

// ParseError is a parse failure located to a line and column (both 1-based).
type ParseError struct {
	Line   int
	Column int
	Err    error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("format error at line %d, column %d: %v", e.Line, e.Column, e.Err)
}

// ParseResult holds the parsed object and, in non-strict mode, any per-line
// errors that were skipped.
type ParseResult struct {
	Object map[string]interface{}
	Errors []*ParseError
}

// ParseObject parses an object from input. Blank lines and lines beginning with
// '#' are ignored. In strict mode any error returns immediately; otherwise
// errors are collected in the result and only a wholly unparseable input is an
// error.
func (p *ObjectParser) ParseObject(input string) (result *ParseResult, err error) {
	// A malformed object must never crash the caller: this runs on
	// machine-generated files that can be read mid-write, and the SFTP request
	// server does not recover per-operation. The byte cursor is bounds-safe, so
	// this is defense in depth rather than load-bearing.
	defer func() {
		if r := recover(); r != nil {
			result, err = nil, fmt.Errorf("panic while parsing object: %v", r)
		}
	}()

	if input == "" {
		return nil, fmt.Errorf("input string is empty")
	}

	result = &ParseResult{Object: make(map[string]interface{})}
	for lineNum, line := range strings.Split(input, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}

		lp := newLineParser(line)
		key, value, lineErr := lp.parseLine()
		if lineErr != nil {
			pe := &ParseError{Line: lineNum + 1, Column: lp.pos + 1, Err: lineErr}
			if p.strict {
				return nil, pe
			}
			result.Errors = append(result.Errors, pe)
			continue
		}
		result.Object[key] = value
	}

	if len(result.Object) == 0 && len(result.Errors) > 0 {
		return nil, fmt.Errorf("no valid entries found")
	}
	return result, nil
}

// lineParser is a byte cursor over a single line.
type lineParser struct {
	s   string
	pos int
}

func newLineParser(line string) *lineParser {
	return &lineParser{s: line}
}

// peek returns the byte n positions ahead of the cursor, or 0 at end of input.
func (p *lineParser) peek(n int) byte {
	if i := p.pos + n; i < len(p.s) {
		return p.s[i]
	}
	return 0
}

// accept consumes the next byte if it equals b.
func (p *lineParser) accept(b byte) bool {
	if p.peek(0) == b {
		p.pos++
		return true
	}
	return false
}

// match consumes prefix s if the cursor is positioned at it.
func (p *lineParser) match(s string) bool {
	if strings.HasPrefix(p.s[p.pos:], s) {
		p.pos += len(s)
		return true
	}
	return false
}

// skipSpaces advances past spaces and tabs.
func (p *lineParser) skipSpaces() {
	for p.peek(0) == ' ' || p.peek(0) == '\t' {
		p.pos++
	}
}

// parseLine parses one "key value" line and returns the key and value.
func (p *lineParser) parseLine() (string, interface{}, error) {
	switch p.peek(0) {
	case '#', '\n', 0:
		return "", nil, nil // comment or empty line
	case ' ', '\t':
		return "", nil, fmt.Errorf("leading whitespace not allowed")
	}

	key, err := p.parseIdentifier()
	if err != nil {
		return "", nil, err
	}

	if !p.accept(' ') {
		return "", nil, fmt.Errorf("expected a single space after the key")
	}
	if p.peek(0) == ' ' || p.peek(0) == '\t' {
		return "", nil, fmt.Errorf("only a single space is allowed after the key")
	}

	value, err := p.parseValue()
	if err != nil {
		return "", nil, err
	}

	switch p.peek(0) {
	case ' ', '\t':
		return "", nil, fmt.Errorf("trailing whitespace not allowed")
	case '\n', 0:
		return key, value, nil
	default:
		return "", nil, fmt.Errorf("expected end of line")
	}
}

// parseValue parses any value, dispatching on the leading byte.
func (p *lineParser) parseValue() (interface{}, error) {
	p.skipSpaces()

	switch b := p.peek(0); {
	case b == '"':
		return p.parseString()
	case b == '-' || isDigit(b):
		return p.parseNumber()
	case b == '(':
		switch p.peek(1) {
		case '{':
			return p.parseArray()
		case '[':
			return p.parseMap()
		}
		return nil, fmt.Errorf("expected '({' or '([' after '('")
	case b == 'n':
		start := p.pos
		if p.match("nil") && isTerminator(p.peek(0)) {
			return nil, nil
		}
		p.pos = start
		return nil, fmt.Errorf("invalid nil value")
	}
	return nil, fmt.Errorf("unexpected character %q", string(p.peek(0)))
}

// parseString parses a double-quoted string with escape sequences. Unknown
// escapes are taken literally (matching DGD). Newlines are not allowed.
func (p *lineParser) parseString() (string, error) {
	if !p.accept('"') {
		return "", fmt.Errorf(`expected '"'`)
	}

	var b strings.Builder
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		p.pos++
		switch c {
		case '"':
			return b.String(), nil
		case '\n':
			return "", fmt.Errorf("newline in string")
		case '\\':
			if p.pos >= len(p.s) {
				return "", fmt.Errorf("unterminated string")
			}
			if esc, ok := escapeSequences[p.s[p.pos]]; ok {
				p.pos++
				b.WriteByte(esc)
			} else {
				// Unknown escape: take the next character literally, decoding a
				// full rune so multibyte content survives.
				r, w := utf8.DecodeRuneInString(p.s[p.pos:])
				p.pos += w
				b.WriteRune(r)
			}
		default:
			b.WriteByte(c) // raw byte; preserves UTF-8 payload
		}
	}
	return "", fmt.Errorf("unterminated string")
}

// parseNumber parses an integer or a float. Floats are [-]digits[.digits] with
// an optional "=hexdigits" tail holding the exact IEEE-754 bits, which DGD
// emits and which we parse from the decimal form and otherwise ignore.
func (p *lineParser) parseNumber() (interface{}, error) {
	start := p.pos
	p.accept('-')

	intDigits := 0
	for isDigit(p.peek(0)) {
		p.pos++
		intDigits++
	}

	isFloat := false
	if p.accept('.') {
		isFloat = true
		fracDigits := 0
		for isDigit(p.peek(0)) {
			p.pos++
			fracDigits++
		}
		if fracDigits == 0 {
			return nil, fmt.Errorf("float must have digits after the decimal point")
		}
	}
	if p.accept('=') {
		isFloat = true
		hexDigits := 0
		for isHexDigit(p.peek(0)) {
			p.pos++
			hexDigits++
		}
		if hexDigits == 0 {
			return nil, fmt.Errorf("float must have hex digits after '='")
		}
	}

	tok := p.s[start:p.pos]
	if isFloat {
		if intDigits == 0 {
			return nil, fmt.Errorf("float must start with a digit")
		}
		decimal := tok
		if i := strings.IndexByte(decimal, '='); i >= 0 {
			decimal = decimal[:i] // drop the hex-bits tail
		}
		f, err := strconv.ParseFloat(decimal, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid float %q", tok)
		}
		return f, nil
	}

	n, err := strconv.Atoi(tok)
	if err != nil {
		return nil, fmt.Errorf("invalid integer %q", tok)
	}
	return n, nil
}

// parseCount parses a non-negative element/entry count.
func (p *lineParser) parseCount() (int, error) {
	start := p.pos
	for isDigit(p.peek(0)) {
		p.pos++
	}
	if p.pos == start {
		return 0, fmt.Errorf("expected a count")
	}
	return strconv.Atoi(p.s[start:p.pos])
}

// parseArray parses an array: ({size|v1,v2,...}). size must match the element
// count. A single trailing comma is allowed.
func (p *lineParser) parseArray() ([]interface{}, error) {
	if !p.match("({") {
		return nil, fmt.Errorf("array: expected '({'")
	}
	size, err := p.parseCount()
	if err != nil {
		return nil, fmt.Errorf("array: %w", err)
	}
	if !p.accept('|') {
		return nil, fmt.Errorf("array: expected '|' after size")
	}

	elements := []interface{}{}

	p.skipSpaces()
	if p.match("})") || p.match(",})") { // empty, optionally with trailing comma
		if size != 0 {
			return nil, fmt.Errorf("array: empty but size is %d", size)
		}
		return elements, nil
	}

	for {
		el, err := p.parseValue()
		if err != nil {
			return nil, fmt.Errorf("array: %w", err)
		}
		elements = append(elements, el)

		p.skipSpaces()
		if p.accept(',') {
			p.skipSpaces()
			if p.match("})") { // trailing comma
				break
			}
			continue
		}
		if p.match("})") {
			break
		}
		return nil, fmt.Errorf("array: expected ',' or '})'")
	}

	if len(elements) != size {
		return nil, fmt.Errorf("array: expected %d elements, got %d", size, len(elements))
	}
	return elements, nil
}

// parseMap parses a mapping: ([size|k1:v1,k2:v2,...]). size counts all entries
// including complex-keyed ones that are skipped. A single trailing comma is
// allowed.
func (p *lineParser) parseMap() (map[string]interface{}, error) {
	if !p.match("([") {
		return nil, fmt.Errorf("map: expected '(['")
	}
	size, err := p.parseCount()
	if err != nil {
		return nil, fmt.Errorf("map: %w", err)
	}
	if !p.accept('|') {
		return nil, fmt.Errorf("map: expected '|' after size")
	}

	result := make(map[string]interface{})

	p.skipSpaces()
	if p.match("])") {
		if size != 0 {
			return nil, fmt.Errorf("map: empty but size is %d", size)
		}
		return result, nil
	}

	total := 0
	for {
		key, value, skipped, err := p.parseMapEntry()
		if err != nil {
			return nil, err
		}
		total++
		if !skipped {
			result[key] = value
		}

		p.skipSpaces()
		if p.accept(',') {
			p.skipSpaces()
			if p.match("])") { // trailing comma
				break
			}
			continue
		}
		if p.match("])") {
			break
		}
		return nil, fmt.Errorf("map: expected ',' or '])'")
	}

	if total != size {
		return nil, fmt.Errorf("map: expected %d entries, got %d", size, total)
	}
	return result, nil
}

// parseMapEntry parses one key:value pair. Keys must be primitive (string,
// number, or nil); array/map keys are unsupported and the entry is skipped
// (skipped == true) but still counted toward the map size.
func (p *lineParser) parseMapEntry() (key string, value interface{}, skipped bool, err error) {
	p.skipSpaces()

	rawKey, err := p.parseValue()
	if err != nil {
		return "", nil, false, fmt.Errorf("map entry: invalid key: %w", err)
	}

	switch k := rawKey.(type) {
	case string:
		key = k
	case int:
		key = strconv.Itoa(k)
	case float64:
		key = strconv.FormatFloat(k, 'f', -1, 64)
	case nil:
		key = "nil"
	case []interface{}, map[string]interface{}:
		p.skipSpaces()
		if p.accept(':') {
			if _, err := p.parseValue(); err != nil { // consume and discard
				return "", nil, false, err
			}
		}
		return "", nil, true, nil
	default:
		return "", nil, false, fmt.Errorf("map entry: unsupported key type %T", rawKey)
	}

	p.skipSpaces()
	if !p.accept(':') {
		return "", nil, false, fmt.Errorf("map entry: expected ':' after key")
	}

	value, err = p.parseValue()
	if err != nil {
		return "", nil, false, err
	}
	return key, value, false, nil
}

// parseIdentifier parses a key: an ASCII letter followed by letters, digits,
// and underscores.
func (p *lineParser) parseIdentifier() (string, error) {
	start := p.pos
	if !isLetter(p.peek(0)) {
		return "", fmt.Errorf("identifier must start with a letter")
	}
	p.pos++
	for isIdentChar(p.peek(0)) {
		p.pos++
	}
	return p.s[start:p.pos], nil
}

// escapeSequences maps the character after a backslash to its literal byte.
var escapeSequences = map[byte]byte{
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

func isDigit(b byte) bool  { return b >= '0' && b <= '9' }
func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

func isIdentChar(b byte) bool { return isLetter(b) || isDigit(b) || b == '_' }

func isHexDigit(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// isTerminator reports whether b can validly follow a bare value (nil).
func isTerminator(b byte) bool {
	switch b {
	case ',', ':', ']', '}', ')', '\n', 0:
		return true
	}
	return false
}
