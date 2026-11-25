package core

import "testing"

func TestSearchDomain(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"lan", "lan", true},
		{"corp.example.com.", "corp.example.com", true},
		{"home\x00", "home", true},
		{"_srv.example", "_srv.example", true},
		{"lan\nnameserver 6.6.6.6", "", false},
		{"a b", "", false},
		{"options ndots:15", "", false},
		{"bad..dots", "", false},
		{"-lead.example", "", false},
		{"", "", false},
		{"\x00", "", false},
	}
	for _, c := range cases {
		got, ok := SearchDomain(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("SearchDomain(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func FuzzSearchDomain(f *testing.F) {
	f.Add("example.com")
	f.Add("lan\x00")
	f.Fuzz(func(t *testing.T, in string) {
		d, ok := SearchDomain(in)
		if !ok {
			return
		}
		for i := 0; i < len(d); i++ {
			if c := d[i]; c <= ' ' || c >= 0x7f || c == '#' || c == ';' {
				t.Fatalf("accepted %q with byte %#x", d, c)
			}
		}
		if again, ok := SearchDomain(d); !ok || again != d {
			t.Fatalf("not stable: %q -> %q", d, again)
		}
	})
}
