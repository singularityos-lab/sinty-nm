package nmapi

import (
	"strings"

	"github.com/godbus/dbus/v5"
)

// Profiles written before typed keyfile values stored list settings in Go's
// fmt form, e.g. [map[address:"10.0.0.2" prefix:@u 32]] or [1.1.1.1 9.9.9.9].
var legacyMapKeys = map[string]bool{"address-data": true, "route-data": true, "routing-rules": true, "peers": true}
var legacyListKeys = map[string]bool{"dns-data": true, "dns-search": true, "dns-options": true, "allowed-ips": true}

func legacyVariant(key, val string) (dbus.Variant, bool) {
	if !strings.HasPrefix(val, "[") || !strings.HasSuffix(val, "]") {
		return dbus.Variant{}, false
	}
	inner := strings.TrimSpace(val[1 : len(val)-1])
	switch {
	case legacyMapKeys[key]:
		maps, ok := legacyMaps(inner)
		if !ok {
			return dbus.Variant{}, false
		}
		return dbus.MakeVariant(maps), true
	case legacyListKeys[key]:
		return dbus.MakeVariant(legacyStrings(inner)), true
	}
	return dbus.Variant{}, false
}

func legacyStrings(s string) []string {
	out := []string{}
	for _, f := range strings.Fields(s) {
		out = append(out, strings.Trim(f, `"`))
	}
	return out
}

func legacyMaps(s string) ([]map[string]dbus.Variant, bool) {
	out := []map[string]dbus.Variant{}
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return out, true
		}
		if !strings.HasPrefix(s, "map[") {
			return nil, false
		}
		end := closing(s, 3)
		if end < 0 {
			return nil, false
		}
		m, ok := legacyPairs(s[4:end])
		if !ok {
			return nil, false
		}
		out = append(out, m)
		s = s[end+1:]
	}
}

// closing returns the index of the bracket matching the one at open, honouring quotes.
func closing(s string, open int) int {
	depth := 0
	quoted := false
	for i := open; i < len(s); i++ {
		ch := s[i]
		switch {
		case quoted && ch == '\\':
			i++
		case ch == '"':
			quoted = !quoted
		case quoted:
		case ch == '[' || ch == '<' || ch == '{':
			depth++
		case ch == ']' || ch == '>' || ch == '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func legacyPairs(s string) (map[string]dbus.Variant, bool) {
	m := map[string]dbus.Variant{}
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return m, true
		}
		colon := strings.IndexByte(s, ':')
		if colon <= 0 {
			return nil, false
		}
		key := s[:colon]
		rest := s[colon+1:]
		n := valueEnd(rest)
		raw := strings.TrimSpace(rest[:n])
		v, err := dbus.ParseVariant(raw, dbus.Signature{})
		if err != nil {
			return nil, false
		}
		m[key] = v
		s = rest[n:]
	}
}

// valueEnd finds where a value ends: at a space that starts the next key:value pair.
func valueEnd(s string) int {
	depth := 0
	quoted := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quoted && ch == '\\':
			i++
		case ch == '"':
			quoted = !quoted
		case quoted:
		case ch == '[' || ch == '<' || ch == '{' || ch == '(':
			depth++
		case ch == ']' || ch == '>' || ch == '}' || ch == ')':
			depth--
		case ch == ' ' && depth == 0 && startsPair(s[i+1:]):
			return i
		}
	}
	return len(s)
}

func startsPair(s string) bool {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == ':' {
			return i > 0
		}
		if !(ch == '-' || ch == '_' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return false
}
