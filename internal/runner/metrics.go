//go:build unix

package runner

import (
	"time"

	"github.com/MIERAI/security-platform/internal/runner/config"
	"github.com/MIERAI/security-platform/internal/runner/promtext"
)

// Version is the runner component's version (runner/VERSION; a test keeps them equal).
const Version = "0.10.0"

// row is one job's state as the metrics see it: a local job (with its configuration), a forward-<i> entry, or
// a job a site reported.
type row struct {
	site, name string
	st         State
	job        *config.Job
}

// seriesInput is everything the runner's own series are computed from.
type seriesInput struct {
	site, release string
	now           float64 // timestamps
	decision      float64 // schedule decisions (pending slot)
	maxGap        int64
	sinks         map[string]any
	rows          []row
	jobs          []*config.Job
	loc           *time.Location
}

// runnerSeries builds the runner's series (contract §6, contracts/metrics/registry.json, producer runner).
func runnerSeries(in seriesInput) []promtext.Series {
	site := map[string]string{"site": in.site}
	s := []promtext.Series{
		{Name: "security_runner_tick_timestamp_seconds", Labels: site, Value: promtext.Int(int64(in.now)),
			Help: "Heartbeat of the trigger: when the runner last ticked"},
		{Name: "security_runner_tick_max_gap_seconds", Labels: site, Value: promtext.Int(in.maxGap),
			Help: "The tick heartbeat is overdue after this many seconds (broken trigger, environment or host)"},
	}
	s = append(s, sinkSeries(in.site, in.sinks)...)
	for _, rw := range in.rows {
		s = append(s, jobSeries(rw, in)...)
	}
	s = append(s, collectorIntervals(in)...)
	return append(s, promtext.Series{Name: "security_runner_info",
		Labels: map[string]string{"site": in.site, "version": Version, "release": in.release}, Value: promtext.Int(1),
		Help: "Runner version and the product release it was installed as"})
}

func sinkSeries(site string, sinks map[string]any) []promtext.Series {
	var s []promtext.Series
	for _, key := range sortedKeys(sinks) {
		st, _ := sinks[key].(map[string]any) // not an object: every field reads as absent
		lab := map[string]string{"site": site, "sink": key}
		if v, ok := value(st["last_success"]); ok && truthyNumber(st["last_success"]) {
			s = append(s, promtext.Series{Name: "security_runner_sink_last_success_timestamp_seconds", Labels: lab,
				Value: v, Help: "When the sink last accepted the metrics"})
		}
		s = append(s, promtext.Series{Name: "security_runner_sink_failures_total", Labels: lab,
			Value: valueOr(st["failures_total"]), Help: "Failed deliveries (counter)"},
			promtext.Series{Name: "security_runner_sink_consecutive_failures", Labels: lab,
				Value: valueOr(st["consecutive_failures"]), Help: "Deliveries failed in a row (0 = the last one worked); retried every tick"})
	}
	return s
}

func jobSeries(rw row, in seriesInput) []promtext.Series {
	lab := map[string]string{"site": rw.site, "job": rw.name}
	var s []promtext.Series
	add := func(name string, v promtext.Value, help string) {
		s = append(s, promtext.Series{Name: name, Labels: lab, Value: v, Help: help})
	}
	if v, ok := value(rw.st["last_success"]); ok && truthyNumber(rw.st["last_success"]) {
		add("security_runner_job_last_success_timestamp_seconds", v, "When the job last succeeded")
	}
	if v, ok := value(rw.st["last_attempt"]); ok && truthyNumber(rw.st["last_attempt"]) {
		add("security_runner_job_last_attempt_timestamp_seconds", v, "When the job last started")
	}
	if f, ok := num(rw.st["last_duration"]); ok {
		add("security_runner_job_duration_seconds", promtext.Float(f), "Duration of the last run")
	}
	if v, ok := value(rw.st["last_rc"]); ok {
		add("security_runner_job_last_exit_code", v, "Exit code of the last run (0 = ok)")
	}
	add("security_runner_job_runs_total", valueOr(rw.st["runs_total"]), "Runs (counter)")
	add("security_runner_job_failures_total", valueOr(rw.st["failures_total"]), "Failed runs (counter)")
	if rw.job == nil {
		return s
	}
	add("security_runner_job_expected_interval_seconds", promtext.Int(rw.job.Schedule.Interval(int64(in.now), in.loc)),
		"Seconds between scheduled runs (staleness thresholds derive from it)")
	add("security_runner_job_missed_slots_total", valueOr(rw.st["missed_slots_total"]),
		"Slots that will never run: skipped by max_delay or given up after retries (counter)")
	if slot, ok := pending(Due(rw.job, rw.st, in.decision, in.loc)); ok {
		add("security_runner_job_pending_slot_timestamp_seconds", promtext.Int(slot),
			"The scheduled slot that is due and not done yet (absent when none); lateness = now - value")
	}
	return s
}

func collectorIntervals(in seriesInput) []promtext.Series {
	var s []promtext.Series
	add := func(col string, v int64) {
		s = append(s, promtext.Series{Name: "security_collector_expected_interval_seconds",
			Labels: map[string]string{"collector": col}, Value: promtext.Int(v),
			Help: "Seconds between scheduled runs of the collector"})
	}
	for _, j := range in.jobs {
		if j.Type == config.TypeCollector || j.Type == config.TypeCommand {
			add(j.Report(), j.Schedule.Interval(int64(in.now), in.loc))
		}
		for _, sc := range j.SiteCollectors {
			add(sc.Collector, sc.Schedule.Interval(int64(in.now), in.loc))
		}
	}
	return s
}

// value converts a JSON number to a sample value (integers stay integers, as Python prints them).
func value(v any) (promtext.Value, bool) {
	switch x := v.(type) {
	case int64:
		return promtext.Int(x), true
	case int:
		return promtext.Int(int64(x)), true
	case float64:
		return promtext.Float(x), true
	case bool: // Python prints True/False; a boolean has no place here, so it reads as 1/0
		if x {
			return promtext.Int(1), true
		}
		return promtext.Int(0), true
	default:
		return promtext.Value{}, false
	}
}

func valueOr(v any) promtext.Value {
	if x, ok := value(v); ok {
		return x
	}
	return promtext.Int(0)
}

func truthyNumber(v any) bool {
	f, ok := num(v)
	return ok && f != 0
}
