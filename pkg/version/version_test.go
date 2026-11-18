package version

import "testing"

func TestNormalizeSetAndGet(t *testing.T) {
	prev := Get()
	defer Set(prev)

	cases := []struct {
		in   string
		want string
	}{
		{"", Default},
		{"  ", Default},
		{"dev", Default},
		{"1.1.0", "v1.1.0"},
		{"v1.1.0", "v1.1.0"},
		{"2.0.0-rc1", "v2.0.0-rc1"},
	}
	for _, tc := range cases {
		if got := Normalize(tc.in); got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	Set("1.1.0")
	if got := Get(); got != "v1.1.0" {
		t.Fatalf("Get() = %q, want v1.1.0", got)
	}
}
