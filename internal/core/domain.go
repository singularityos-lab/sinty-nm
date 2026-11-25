package core

import "strings"

// SearchDomain normalizes a DNS search domain from an untrusted source and
// reports whether it is usable. A trailing dot and NUL padding, which some
// routers send in DHCP option 15, are dropped. Anything else that is not a
// hostname is refused, so a value cannot add lines or words to resolv.conf.
func SearchDomain(d string) (string, bool) {
	d = strings.TrimRight(d, "\x00")
	d = strings.TrimSpace(d)
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return "", false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return d, true
}
