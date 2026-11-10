package suwayomi

import (
	"sort"
	"sync"
	"time"
)

// Pacer is a sliding-window pacer that stays quiet until a batch is actually
// running.
//
// A fixed interval taxes everyone equally, so opening a single paid chapter
// paid the same delay as the 100th of a batch -- wrong, because the origin
// does not mind the single read at all. What it minds is ten in a minute.
//
// So the shape is copied from the limiter it has to satisfy. The origin runs
// DRF's SimpleRateThrottle: request timestamps are kept, those older than the
// period are discarded, and once the survivors reach the cap the request is
// refused. Its wording gives it away ("Expected available in N seconds") and
// so does its countdown -- 57, 54, 29, 22 across successive attempts, which
// decrements as entries age out rather than resetting on a boundary. Measured
// against it: the 11th consecutive request is refused, first hint ~57-60s.
// Ten per sixty seconds, sliding.
//
// Mirroring that locally gives three regimes:
//
//   - under Free in the window: no delay at all. Occasional reading never
//     touches this, which is the point.
//   - between there and the cap: a delay ramping from RampMin to RampMax, so a
//     batch decelerates into the limit instead of slamming into it.
//   - at the cap: wait for the oldest entry to leave the window. This is the
//     only hard constraint; everything above it is comfort.
//
// The delay at the cap is not chosen, it falls out: the request must wait
// until the first entry leaves the window, so it pays Window minus whatever
// wall time the preceding ten consumed. Both the ramp's sleeps and the
// requests' own service time count toward that, which makes the worst case
// the *fastest* possible batch. At zero service time it is 21s; at the
// measured p50 of ~2s per request the ten preceding requests absorb 20s of
// the window on their own and the wait drops to 12s, falling further as
// requests get slower. The tests simulate 132 chapters and check that no
// 60-second span ever holds more than ten requests at any service time.
//
// Simulation is how those numbers were checked rather than arithmetic,
// because the free allowance echoes: four requests admitted at once expire at
// once, releasing four slots together a window later. That the echo does not
// breach the cap is not obvious by inspection.
//
// The local window carries a few seconds of margin over the origin's sixty.
// The two clocks are unrelated and the request needs time on the wire, so a
// local window of exactly 60s would let a request land fractionally inside
// the origin's.
type Pacer struct {
	Capacity int
	Window   time.Duration
	Free     int
	RampMin  time.Duration
	RampMax  time.Duration

	Now   func() time.Time
	Sleep func(time.Duration)

	mu      sync.Mutex
	history []time.Time
}

// reserve claims the next permissible slot. The caller sleeps until it.
func (p *Pacer) reserve(now time.Time) time.Time {
	cutoff := now.Add(-p.Window)
	// Entries at or before the cutoff have left the window.
	index := sort.Search(len(p.history), func(i int) bool { return p.history[i].After(cutoff) })
	if index > 0 {
		p.history = append(p.history[:0], p.history[index:]...)
	}

	used := len(p.history)

	earliest := now
	if used >= p.Capacity {
		// The slot cannot open before the entry it displaces ages out.
		earliest = p.history[used-p.Capacity].Add(p.Window)
	}

	soft := now
	if used >= p.Free {
		steps := p.Capacity - p.Free - 1
		k := used - p.Free
		if k > steps {
			k = steps
		}
		fraction := 1.0
		if steps > 0 {
			fraction = float64(k) / float64(steps)
		}
		soft = now.Add(p.RampMin + time.Duration(float64(p.RampMax-p.RampMin)*fraction))
	}

	slot := earliest
	if soft.After(slot) {
		slot = soft
	}
	at := sort.Search(len(p.history), func(i int) bool { return p.history[i].After(slot) })
	p.history = append(p.history, time.Time{})
	copy(p.history[at+1:], p.history[at:])
	p.history[at] = slot
	return slot
}

// Wait blocks until this caller's slot and returns how long that took.
//
// Reserving under the lock and sleeping outside it lets concurrent download
// workers each hold a distinct slot and wait in parallel. Doing both inside
// would serialise the sleeps and multiply the delay by the number of workers.
func (p *Pacer) Wait() time.Duration {
	p.mu.Lock()
	slot := p.reserve(p.Now())
	p.mu.Unlock()
	delay := slot.Sub(p.Now())
	if delay > 0 {
		p.Sleep(delay)
		return delay
	}
	return 0
}
