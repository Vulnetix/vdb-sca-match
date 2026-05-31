package match

import "testing"

func sp(s string) *string { return &s }

func TestDecideVersionRange(t *testing.T) {
	cases := []struct {
		name            string
		version, status string
		versionType     string
		versionValue    *string
		lessThan        *string
		lessThanOrEqual *string
		wantMatch       bool
		wantMethod      string
	}{
		{"below lessThan", "1.5.0", "affected", "semver", nil, sp("2.0.0"), nil, true, "version-range:lessThan"},
		{"at lessThan (exclusive)", "2.0.0", "affected", "semver", nil, sp("2.0.0"), nil, false, ""},
		{"above lessThan", "3.0.0", "affected", "semver", nil, sp("2.0.0"), nil, false, ""},
		{"at lessThanOrEqual (inclusive)", "2.0.0", "affected", "semver", nil, nil, sp("2.0.0"), true, "version-range:lessThanOrEqual"},
		{"exact versionValue", "1.0.0", "affected", "semver", sp("1.0.0"), nil, nil, true, "version-range:exact"},
		{"unaffected status never matches", "1.0.0", "unaffected", "semver", sp("1.0.0"), sp("9.9.9"), nil, false, ""},
		{"empty version never matches", "", "affected", "semver", sp("1.0.0"), nil, nil, false, ""},
		{"unparseable falls back to string-equality exact", "not-semver", "affected", "semver", sp("not-semver"), nil, nil, true, "version-range:exact"},
		{"generic numeric ordering", "1.2.9", "affected", "generic", nil, sp("1.2.10"), nil, true, "version-range:lessThan"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotMatch, gotMethod := decideVersionRange(c.version, c.status, c.versionType, c.versionValue, c.lessThan, c.lessThanOrEqual)
			if gotMatch != c.wantMatch || gotMethod != c.wantMethod {
				t.Fatalf("decideVersionRange(%q,%q,…) = (%v,%q), want (%v,%q)",
					c.version, c.status, gotMatch, gotMethod, c.wantMatch, c.wantMethod)
			}
		})
	}
}

func TestBuildRangeString(t *testing.T) {
	cases := []struct {
		versionValue, lessThan, lessThanOrEqual *string
		want                                    string
	}{
		{sp("1.0.0"), sp("2.0.0"), nil, ">=1.0.0, <2.0.0"},
		{nil, nil, sp("3.0.0"), "<=3.0.0"},
		{sp("1.0.0"), nil, nil, ">=1.0.0"},
		{nil, nil, nil, ""},
	}
	for _, c := range cases {
		if got := buildRangeString(c.versionValue, c.lessThan, c.lessThanOrEqual); got != c.want {
			t.Errorf("buildRangeString = %q, want %q", got, c.want)
		}
	}
}
