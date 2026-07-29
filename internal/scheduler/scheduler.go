// Package scheduler periodically triggers scans for programs with an
// enabled recurring schedule, using the same recon.Engine instance as
// manual scans so cancellation/timeout behavior is identical either way.
package scheduler

import (
	"context"
	"log"
	"time"

	"bbtracker/internal/recon"
	"bbtracker/internal/store"
)

// tickInterval is how often we check for due programs. It's independent of
// any program's own schedule interval (minimum 1 day) - checking every
// minute is cheap and gives good-enough scheduling resolution.
const tickInterval = time.Minute

type Scheduler struct {
	st     *store.Store
	engine *recon.Engine
}

func New(st *store.Store, engine *recon.Engine) *Scheduler {
	return &Scheduler{st: st, engine: engine}
}

// Run blocks, checking for due programs on each tick, until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	s.tick() // catch up immediately on startup rather than waiting a full tickInterval
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick()
		}
	}
}

func (s *Scheduler) tick() {
	due, err := s.st.DuePrograms()
	if err != nil {
		log.Printf("scheduler: list due programs: %v", err)
		return
	}
	for _, p := range due {
		running, err := s.st.RunningScanForProgram(p.ID)
		if err != nil {
			log.Printf("scheduler: check running scan for program %d: %v", p.ID, err)
			continue
		}
		if running > 0 {
			continue // a scan (manual or scheduled) is already in flight; try again next tick
		}

		opts := store.ScanOptions{
			RunSubfinder:       p.ScheduleRunSubfinder,
			RunHTTPX:           p.ScheduleRunHTTPX,
			Screenshot:         p.ScheduleScreenshot,
			RunNuclei:          p.ScheduleRunNuclei,
			RunFuzz:            p.ScheduleRunFuzz,
			FuzzWordlistPath:   p.ScheduleFuzzWordlistPath,
			RunWayback:         p.ScheduleRunWayback,
			RunParams:          p.ScheduleRunParams,
			ParamsWordlistPath: p.ScheduleParamsWordlistPath,
			RunJSAnalysis:      p.ScheduleRunJSAnalysis,
			RunCORS:            p.ScheduleRunCORS,
			RunGithubDork:      p.ScheduleRunGithubDork,
			RunCloudEnum:       p.ScheduleRunCloudEnum,
			RunTakeover:        p.ScheduleRunTakeover,
			RunTLS:             p.ScheduleRunTLS,
			RunDNS:             p.ScheduleRunDNS,
			RunUncover:         p.ScheduleRunUncover,
			RunCrawl:           p.ScheduleRunCrawl,
		}
		scanID, err := s.st.CreateScan(p.ID, opts, "scheduled")
		if err != nil {
			log.Printf("scheduler: create scan for program %d: %v", p.ID, err)
			continue
		}
		if err := s.st.MarkScheduleRun(p.ID); err != nil {
			log.Printf("scheduler: mark schedule run for program %d: %v", p.ID, err)
		}
		log.Printf("scheduler: starting scheduled scan %d for program %d (%s)", scanID, p.ID, p.Name)
		go s.engine.Run(context.Background(), p.ID, scanID, opts)
	}
}
