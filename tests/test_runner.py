"""runner: cron schedules, due/catch-up/jitter/retry logic, locking, timeouts, a full tick with a command job."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "runner"), ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "core")]
os.environ["TZ"] = "UTC"
time.tzset()
import cron  # noqa: E402
import runner  # noqa: E402

FX = os.path.join(ROOT, "tests", "fixtures", "host.findings.json")


def T(s):  # "2026-01-05 03:30" UTC -> epoch
    return int(time.mktime(time.strptime(s, "%Y-%m-%d %H:%M")))


class Cron(unittest.TestCase):
    def test_prev_next(self):
        c = cron.Cron("30 3 * * *")
        self.assertEqual(c.prev(T("2026-01-05 03:29")), T("2026-01-04 03:30"))
        self.assertEqual(c.prev(T("2026-01-05 03:30")), T("2026-01-05 03:30"))
        self.assertEqual(c.next(T("2026-01-05 03:30")), T("2026-01-06 03:30"))
        self.assertEqual(c.interval(T("2026-01-05 00:00")), 86400)

    def test_lists_ranges_steps_dow(self):
        self.assertEqual(cron.Cron("*/15 * * * *").interval(T("2026-01-05 00:00")), 900)
        c = cron.Cron("0 9 * * 1")            # Mondays; 2026-01-05 is a Monday
        self.assertEqual(c.prev(T("2026-01-11 12:00")), T("2026-01-05 09:00"))
        self.assertEqual(cron.Cron("0 9 * * 7").prev(T("2026-01-11 12:00")), T("2026-01-11 09:00"))   # 7 = Sunday
        c = cron.Cron("0 0 1 * 1")            # dom OR dow when both restricted
        self.assertTrue(c.matches(T("2026-01-05 00:00")) and c.matches(T("2026-02-01 00:00")))
        self.assertEqual(sorted(cron._field("1-10/3", 0, 59)), [1, 4, 7, 10])
        for bad in ("* * *", "61 * * * *", "*/0 * * * *"):
            with self.assertRaises(ValueError):
                cron.Cron(bad)

    def test_durations(self):
        self.assertEqual([cron.parse_duration(x) for x in ("90s", "30m", "2h", "1d", 45, None)], [90, 1800, 7200, 86400, 45, 0])


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.data = os.path.join(self.d, "data")
        os.makedirs(self.data)

    def tearDown(self):
        shutil.rmtree(self.d)

    def instance(self, jobs, **runner_cfg):
        p = os.path.join(self.d, "instance.json")    # JSON: the runner needs no PyYAML
        json.dump({"name": "test", "runner": dict({"site": "hub", "role": "hub", "jobs": jobs}, **runner_cfg)}, open(p, "w"))
        return p


class Due(Base):
    def test_catch_up_jitter_retry_max_delay(self):
        r = runner.Runner(self.instance({"a": {"schedule": "30 3 * * *", "retries": 1, "retry_delay": "20m"},
                                         "b": {"schedule": "30 3 * * *", "max_delay": "3h"},
                                         "c": {"schedule": "30 3 * * *", "jitter": "1h"}}), self.data)
        now = T("2026-01-05 12:00")
        slot, why = r.due("a", now)
        self.assertEqual((slot, why), (T("2026-01-05 03:30"), "due"))       # missed slot: caught up once
        self.assertEqual(r.due("b", now)[0], None)                         # older than max_delay: skipped
        self.assertEqual(r.due("b", T("2026-01-05 04:00"))[0], T("2026-01-05 03:30"))
        off = r.offset("c", T("2026-01-05 03:30"), 3600)
        self.assertEqual(r.due("c", T("2026-01-05 03:30") + off - 60)[0], T("2026-01-04 03:30"))   # before its jitter
        self.assertEqual(r.due("c", T("2026-01-05 03:30") + off)[0], T("2026-01-05 03:30"))
        st = {"slot": slot, "attempts": 1, "last_attempt": now}
        r.save_state("a", st)
        self.assertEqual(r.due("a", now + 600)[1], "waiting to retry")
        self.assertEqual(r.due("a", now + 1300)[1], "retry 1")
        st["attempts"] = 2
        r.save_state("a", st)
        self.assertEqual(r.due("a", now + 1300)[1], "retries exhausted")
        r.save_state("a", {"done_slot": slot})
        self.assertEqual(r.due("a", now)[1], "done")


class Execute(Base):
    def cmd_job(self, script, **kw):
        p = tempfile.mktemp(suffix=".py", dir=self.d)
        open(p, "w").write(script)
        return dict({"type": "command", "collector": "host", "schedule": "* * * * *", "argv": [sys.executable, p]}, **kw)

    def test_tick_runs_command_job_promotes_merges_and_publishes(self):
        script = f"import os,shutil; shutil.copy({FX!r}, os.path.join(os.environ['SP_RUN_DIR'], 'host.findings.json'))\n"
        out = os.path.join(self.d, "sink", "m.prom")
        inst = self.instance({"host": self.cmd_job(script)}, sinks=[{"type": "textfile", "path": out}])
        self.assertEqual(runner.main(["tick", "--instance", inst, "--data", self.data]), 0)
        st = json.load(open(os.path.join(self.data, "state", "runner", "host.json")))
        self.assertEqual(st["last_rc"], 0, st)
        self.assertTrue(os.path.exists(os.path.join(self.data, "latest", "host.findings.json")))
        self.assertTrue(json.load(open(os.path.join(self.data, "ledger.json")))["entries"])
        text = open(out).read()
        for m in ("security_runner_job_last_success_timestamp_seconds", "security_ledger_last_update_timestamp_seconds",
                  "security_collector_last_run_timestamp_seconds", "security_collector_expected_interval_seconds",
                  "security_sli_new_total", "security_sli_ok"):
            self.assertIn(m, text)
        self.assertEqual(text.count("# TYPE security_runner_job_runs_total "), 1)
        # same slot again: nothing to do
        runner.main(["tick", "--instance", inst, "--data", self.data])
        self.assertEqual(json.load(open(os.path.join(self.data, "state", "runner", "host.json")))["runs_total"], 1)

    def test_failing_sink_is_retried_counted_and_never_fails_the_tick(self):
        blocker = os.path.join(self.d, "not-a-dir")
        open(blocker, "w").close()                        # a path under a regular file: every write fails
        good = os.path.join(self.d, "good.prom")
        inst = self.instance({}, sinks=[{"type": "textfile", "path": os.path.join(blocker, "m.prom")},
                                        {"type": "textfile", "path": good}], tick_stale_after="12h")
        for n in (1, 2):
            self.assertEqual(runner.main(["tick", "--instance", inst, "--data", self.data]), 0)
            local = open(os.path.join(self.data, "metrics", "security-platform.prom")).read()
            self.assertIn(f'security_runner_sink_consecutive_failures{{sink="0-textfile",site="hub"}} {n}', local)
            self.assertIn('security_runner_sink_consecutive_failures{sink="1-textfile",site="hub"} 0', local)
        self.assertIn('security_runner_tick_max_gap_seconds{site="hub"} 43200', open(good).read())
        os.remove(blocker)                                 # the cause is fixed: the next tick delivers
        runner.main(["tick", "--instance", inst, "--data", self.data])
        st = json.load(open(os.path.join(self.data, "state", "runner", "sinks.json")))["0-textfile"]
        self.assertEqual((st["consecutive_failures"], st["failures_total"]), (0, 2))
        self.assertTrue(os.path.exists(os.path.join(blocker, "m.prom")))

    def test_failure_timeout_and_contract(self):
        inst = self.instance({"slow": self.cmd_job("import time; time.sleep(30)", timeout="1s"),
                              "bad": self.cmd_job("import os; open(os.path.join(os.environ['SP_RUN_DIR'],'host.findings.json'),'w').write('{\"schema_version\": \"9.0\"}')",
                                                  collector="host")})
        r = runner.Runner(inst, self.data)
        t0 = time.time()
        self.assertEqual(r.execute("slow"), 124)
        self.assertLess(time.time() - t0, 25)
        self.assertEqual(r.execute("bad"), 65)
        self.assertEqual(r.load_state("bad")["failures_total"], 1)
        self.assertFalse(os.path.exists(os.path.join(self.data, "latest", "host.findings.json")))

    def test_lock_prevents_overlap(self):
        inst = self.instance({"x": self.cmd_job("pass")})
        r = runner.Runner(inst, self.data)
        held = r.lock("x")
        self.assertIsNotNone(held)
        self.assertIsNone(r.execute("x"))   # skipped, not run twice
        held.close()

    def test_site_role_fills_outbox_and_hub_ingests(self):
        script = f"import os,shutil; shutil.copy({FX!r}, os.path.join(os.environ['SP_RUN_DIR'], 'host.findings.json'))\n"
        site_data, outbox, sstate = os.path.join(self.d, "site"), os.path.join(self.d, "outbox"), os.path.join(self.d, "sstate")
        site_inst = os.path.join(self.d, "site.json")
        json.dump({"name": "t", "runner": {"site": "vantage", "role": "site", "outbox": {"type": "local", "dir": outbox},
                                            "state_outbox": {"type": "local", "dir": sstate},
                                            "jobs": {"host": self.cmd_job(script)}}}, open(site_inst, "w"))
        runner.main(["run", "host", "--instance", site_inst, "--data", site_data])
        self.assertEqual(len([f for f in os.listdir(outbox) if f.endswith(".findings.json")]), 1)
        self.assertFalse(os.path.exists(os.path.join(site_data, "ledger.json")))     # sites keep no ledger
        hub = self.instance({"ingest-vantage": {"type": "ingest", "schedule": "*/30 * * * *", "site": "vantage",
                                                "source": {"type": "local", "dir": outbox}, "site_state": sstate,
                                                "site_collectors": {"host": "30 3 * * *"}}},
                            sinks=[{"type": "textfile", "path": os.path.join(self.d, "m.prom")}])
        self.assertEqual(runner.main(["run", "ingest-vantage", "--instance", hub, "--data", self.data]), 0)
        self.assertTrue(json.load(open(os.path.join(self.data, "ledger.json")))["entries"])
        self.assertEqual([f for f in os.listdir(outbox) if f.endswith(".json")], [])   # acknowledged
        text = open(os.path.join(self.d, "m.prom")).read()
        self.assertIn('security_runner_job_last_success_timestamp_seconds{job="host",site="vantage"}', text)
        self.assertIn('security_collector_expected_interval_seconds{collector="host"} 86400', text)


if __name__ == "__main__":
    unittest.main()
