package suwayomi

import (
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Sleep(d time.Duration)   { c.t = c.t.Add(d) }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newPacer(clock *fakeClock) *Pacer {
	return &Pacer{
		Capacity: 10, Window: 63 * time.Second, Free: 4,
		RampMin: 2 * time.Second, RampMax: 12 * time.Second,
		Now: clock.Now, Sleep: clock.Sleep,
	}
}

// The origin allows ten per sixty seconds, sliding. Over a long batch no
// sixty-second span may hold more than ten requests, whatever the service time.
func TestPacerNeverExceedsTheOriginLimit(t *testing.T) {
	for _, service := range []time.Duration{0, 500 * time.Millisecond, 2 * time.Second, 5 * time.Second} {
		clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
		pacer := newPacer(clock)
		var sent []time.Time
		for i := 0; i < 132; i++ {
			pacer.Wait()
			sent = append(sent, clock.Now())
			clock.Advance(service)
		}
		for i := range sent {
			inWindow := 0
			for j := i; j < len(sent) && sent[j].Sub(sent[i]) < 60*time.Second; j++ {
				inWindow++
			}
			if inWindow > 10 {
				t.Fatalf("service %v: %d requests within 60s starting at #%d", service, inWindow, i)
			}
		}
	}
}

func TestPacerIsFreeForOccasionalReads(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	pacer := newPacer(clock)
	for i := 0; i < 4; i++ {
		if waited := pacer.Wait(); waited != 0 {
			t.Fatalf("read %d waited %v, want 0", i+1, waited)
		}
	}
	// The fifth starts the ramp at RampMin.
	if waited := pacer.Wait(); waited != 2*time.Second {
		t.Fatalf("fifth read waited %v, want 2s", waited)
	}
}

// At zero service time the wait at the cap is 21s, as the design note says.
func TestPacerWaitAtTheCap(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	pacer := newPacer(clock)
	var last time.Duration
	for i := 0; i < 11; i++ {
		last = pacer.Wait()
	}
	if last != 21*time.Second {
		t.Fatalf("11th read waited %v, want 21s", last)
	}
}
