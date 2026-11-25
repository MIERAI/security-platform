# Scale: measured limits

How the core stages behave as the number of assets and findings grows, measured with `bench/scale.py` (synthetic
findings, nothing environment-specific). Re-run it on your own hardware before relying on the numbers:

```
python bench/scale.py                                                    # smoke size (also a unit test)
python bench/scale.py --sizes 1000:100,10000:1000,100000:10000 --runs 4 --parallel 3 --out results.json
python bench/scale.py --sizes 10000:1000 --runs 30 --stages ledger      # growth of the ledger over many runs
```

## What the benchmark does

- Five collectors (`vuln-intel` 60 % of the findings, `k8s` 15 %, `host` 12 %, `secrets-files` 8 %, `exposure` 5 %),
  findings documents in the findings/v1 contract, coverage per asset (hosts, images with three tags, clusters as
  umbrella coverage, endpoints). Assets: 40 % hosts, 40 % images, 20 % workloads.
- Repeated runs with churn: in every run after the first, 5 % of each collector's findings disappear (fixed when the
  asset was covered) and as many new ones appear; 1 % of the hosts are a coverage gap; about 1 % of the findings have
  a human-approved exception, one in five of them expired.
- After every run, each stage runs as its own process: `core/ledger.py` (merge, lifecycle, SLIs, `ledger.prom`,
  `latest-auto.md`, `ocsf.jsonl`), `scorecard.py compute`, `core/digest.py`, `core/remediation.py` (default `files`
  tracker). Wall time and peak RSS are those of that process alone (`os.wait4`).

## Results (core 0.6.3, Python 3.12, one Apple M4 Pro core per stage, local SSD; three sizes in parallel)

Seconds / peak RSS MiB per stage. "entries" includes the fixed entries the ledger keeps.

| findings per run | assets | run | ledger entries | ledger.json | ledger | scorecard | digest | remediation |
|---|---|---|---|---|---|---|---|---|
| 1k | 100 | 1 | 950 | 0.8 MiB | 0.08 s / 27 | 0.21 s / 32 | 0.04 s / 25 | 0.38 s / 27 |
| 1k | 100 | 4 | 1 075 | 0.9 MiB | 0.19 s / 30 | 0.39 s / 33 | 0.09 s / 28 | 0.33 s / 29 |
| 10k | 1k | 1 | 9 500 | 8.1 MiB | 0.48 s / 57 | 0.27 s / 67 | 0.11 s / 60 | 3.7 s / 73 |
| 10k | 1k | 4 | 10 765 | 9.3 MiB | 0.80 s / 91 | 0.39 s / 72 | 0.23 s / 81 | 2.8 s / 87 |
| 100k | 10k | 1 | 95 000 | 81 MiB | 5.2 s / 356 | 0.63 s / 414 | 1.0 s / 418 | 37 s / 497 |
| 100k | 10k | 4 | 107 613 | 93 MiB | 5.8 s / 700 | 0.70 s / 468 | 1.8 s / 655 | 48 s / 655 |

Before core 0.6.3 the ledger merge of a repeat run took **30-32 s** at 100k findings (5 s for the first run): every
finding that disappeared or appeared was checked against every coverage entry of the run (`covered()` scanned the
whole list), i.e. O(churn × coverage). Core 0.6.3 indexes the coverage once per document (`ledger.Coverage`), same
rules (`tests/test_scale.py` compares it with the linear rule on random inputs); the cost is now dominated by reading
and writing `ledger.json`.

Growth over many runs (5 % churn per run, ledger + scorecard + digest):

| findings per run | run | ledger entries | ledger.json | ledger | scorecard | digest |
|---|---|---|---|---|---|---|
| 10k | 30 | 20 765 | 19 MiB | 0.79 s / 137 | 0.26 s / 115 | 0.25 s / 112 |
| 100k | 12 | 139 673 | 123 MiB | 5.7 s / 838 | 0.75 s / 614 | 1.6 s / 619 |

## Limits and what to do about them

- **Up to ~10k open findings / ~1k assets: no limit in sight.** Every stage is below 4 s and 150 MiB, also after 30
  runs. Nothing needs to change.
- **The ledger grows with every fixed finding**, because a fixed entry is kept (regression detection, time to fix).
  Its size is "open findings + everything ever fixed", not "open findings": at 10k open findings and 5 % daily churn
  it doubles in about a month. Memory of every stage that loads the ledger is about **4-6 MiB per 1 000 entries**;
  the ledger process reaches **~1 GiB at ~180k entries** (extrapolated from 838 MiB at 140k) (scorecard, digest and remediation somewhat later).
- **The `files` tracker is the slowest stage at 100k** (37-48 s per run; ~19 s when nothing changed, about half of it
  opening one markdown file per item). It is linear, and below 4 s at 10k. An instance at that size should use an
  external tracker or accept the time; the runner's job timeouts must allow it.
- **The ledger is one JSON document, read and rewritten in full by each run** (`ledger.json`, plus `digest`,
  `remediation`, `scorecard` and snapshots read it whole). At 100k findings that is most of the ~5 s per run:
  acceptable. No alternative storage backend is provided because none is needed at the sizes this
  product targets; if an instance approaches ~150k ledger entries, the options in order are: (1) an archive/retention
  rule for entries fixed long ago (a ledger contract change, two-step per docs/upgrade.md), (2) a storage backend
  behind an interface (e.g. SQLite) that still exports `ledger.json` for the consumers.
- Not measured here: collectors themselves (their cost is the target environment), the runner's hub ingest of many
  sites (each site document is merged by the same ledger code), metrics cardinality (labels never carry assets, so
  series do not grow with assets).
