package version

import "testing"

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.0", 0, true},
		{"1.0.0", "1.0.1", -1, true},
		{"1.0.1", "1.0.0", 1, true},
		{"2.0.0", "1.9.9", 1, true},
		{"v1.6.3", "v1.7.0", -1, true},
		{"4.17.20", "4.17.21", -1, true},
		{"1.0.0-alpha", "1.0.0", -1, true},
		{"", "1.0.0", 0, false},
		{"latest", "1.0.0", 0, false},
		{"*", "1.0.0", 0, false},
	}
	for _, c := range cases {
		got, ok := Compare("npm", "semver", c.a, c.b)
		if ok != c.ok {
			t.Errorf("Compare(%q,%q) ok=%v want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestComparePEP440(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.0", 0, true},
		{"1.0.0.post1", "1.0.0", 1, true},
		{"1.0.0a1", "1.0.0", -1, true},
		{"2.0.0", "1.9.9", 1, true},
	}
	for _, c := range cases {
		got, ok := Compare("pypi", "pep440", c.a, c.b)
		if ok != c.ok {
			t.Errorf("Compare(%q,%q) ok=%v want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareMaven(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.0", 0, true},
		{"1.0-SNAPSHOT", "1.0", -1, true},
		{"1.0", "1.0-SNAPSHOT", 1, true},
		{"2.0", "1.9", 1, true},
	}
	for _, c := range cases {
		got, ok := Compare("maven", "maven", c.a, c.b)
		if ok != c.ok {
			t.Errorf("Compare(%q,%q) ok=%v want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareGeneric(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"2.0", "1.9", 1},
		{"1.0-1", "1.0-2", -1},
	}
	for _, c := range cases {
		got, ok := Compare("deb", "", c.a, c.b)
		if !ok {
			t.Errorf("Compare(%q,%q) ok=false want true", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestWithin(t *testing.T) {
	cases := []struct {
		version, lower, lt, lte string
		want                    bool
	}{
		{"1.5.0", "1.0.0", "2.0.0", "", true},
		{"2.5.0", "1.0.0", "2.0.0", "", false},
		{"1.0.0", "1.0.0", "", "2.0.0", true},
		{"2.0.0", "1.0.0", "", "2.0.0", true},
		{"2.1.0", "1.0.0", "", "2.0.0", false},
		{"1.5.0", "", "2.0.0", "", true},
		{"1.5.0", "", "", "2.0.0", true},
		{"0.5.0", "1.0.0", "2.0.0", "", false},
	}
	for _, c := range cases {
		got, _ := Within("npm", "semver", c.version, c.lower, c.lt, c.lte)
		if got != c.want {
			t.Errorf("Within(%q, %q, %q, %q)=%v want %v", c.version, c.lower, c.lt, c.lte, got, c.want)
		}
	}
}
