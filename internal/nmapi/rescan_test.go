package nmapi

import (
	"testing"
	"time"
)

func TestRescanFollowsClientInterest(t *testing.T) {
	now := time.Now()
	cases := []struct {
		wanted time.Time
		want   bool
	}{
		{time.Time{}, false},
		{now, true},
		{now.Add(-scanInterest), true},
		{now.Add(-scanInterest - time.Second), false},
	}
	for _, c := range cases {
		if got := rescanDue(now, c.wanted); got != c.want {
			t.Errorf("rescanDue(now, %v) = %v, want %v", now.Sub(c.wanted), got, c.want)
		}
	}
}
