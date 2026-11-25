// Package runner is the Go implementation of the runner (contracts/runner/SPEC.md): `sp runner tick|run|status|
// metrics|serve-metrics|version`. It schedules, locks, runs and records jobs itself and writes the same state, log
// and metrics formats as the Python runner (runner/runner.py), so one data directory works with either. Job types
// and adapters that are still Python only (ingest, push, snapshot, pull-snapshot, spools, non-file sinks, findings
// validation) run through runner/bridge.py with the Python runner's own code.
//
// The runner needs a Unix-like system (process groups, sessions, flock): on other systems `sp runner` says so.
package runner
