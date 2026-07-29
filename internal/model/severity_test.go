package model

import "testing"

func TestSeverityFor(t *testing.T) {
	cases := map[float64]string{
		10:  "Disaster",
		9.8: "Disaster",
		9:   "Disaster",
		8.9: "High",
		7:   "High",
		6.9: "Average",
		4:   "Average",
		3.9: "Warning",
		0:   "Warning",
		-1:  "Warning", // clamp
	}
	for score, want := range cases {
		if got := SeverityFor(score).Label; got != want {
			t.Errorf("SeverityFor(%v) = %q, want %q", score, got, want)
		}
	}
}
