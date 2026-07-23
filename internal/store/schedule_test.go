package store

import (
	"testing"
	"time"
)

func TestNextOccurrence(t *testing.T) {
	from := parseTest(t, "2026-07-11 10:00:00")

	// Time later today -> today.
	got, err := nextOccurrence("15:04", from)
	if err != nil {
		t.Fatal(err)
	}
	if want := parseTest(t, "2026-07-11 15:04:00"); !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// Time already passed today -> tomorrow.
	got, err = nextOccurrence("03:00", from)
	if err != nil {
		t.Fatal(err)
	}
	if want := parseTest(t, "2026-07-12 03:00:00"); !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if _, err := nextOccurrence("not-a-time", from); err == nil {
		t.Error("expected error for invalid time-of-day")
	}
}

func parseTest(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.ParseInLocation(scheduleTimeLayout, s, time.Local)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}
