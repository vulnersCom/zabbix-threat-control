package selfupdate

import "testing"

func TestIsNewer(t *testing.T) {
	cases := []struct {
		cur, lat string
		want     bool
	}{
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.0", "v1.1.0", true},
		{"v1.0.0", "v2.0.0", true},
		{"1.2.3", "1.2.3", false},
		{"v2.0.0", "v1.9.9", false},
		{"v1.2", "v1.2.1", true},        // missing patch treated as 0
		{"dev", "v1.0.0", false},        // dev builds never nag
		{"v1.0.0", "garbage", false},    // unparseable latest
		{"v1.0.0-rc1", "v1.0.0", false}, // prerelease stripped -> equal
		{"v1.0.0", "v1.0.1-rc1", true},
	}
	for _, c := range cases {
		if got := IsNewer(c.cur, c.lat); got != c.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", c.cur, c.lat, got, c.want)
		}
	}
}
