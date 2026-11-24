"""Minimal 5-field cron schedules (minute hour day-of-month month day-of-week), stdlib only.

Supports `*`, lists `a,b`, ranges `a-b`, steps `*/n` and `a-b/n`, day-of-week 0-7 (0 and 7 = Sunday).
Day-of-month and day-of-week combine as in Vixie cron: when both are restricted, either one matching is enough.
Times are local wall-clock times of the process (set TZ for another zone).
"""
import time

FIELDS = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]


def _field(spec, lo, hi):
    out = set()
    for part in spec.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            step = int(s)
            if step < 1:
                raise ValueError(f"bad step in {spec!r}")
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
        else:
            a = b = int(part)
            if step != 1:
                b = hi
        if not (lo <= a <= hi and lo <= b <= hi and a <= b):
            raise ValueError(f"{spec!r} out of range {lo}-{hi}")
        out.update(range(a, b + 1, step))
    return out


class Cron:
    def __init__(self, expr):
        parts = expr.split()
        if len(parts) != 5:
            raise ValueError(f"cron needs 5 fields: {expr!r}")
        self.expr = expr
        self.minute, self.hour, self.dom, self.month, dow = (_field(p, lo, hi) for p, (lo, hi) in zip(parts, FIELDS))
        self.dow = {d % 7 for d in dow}
        self.dom_any, self.dow_any = parts[2] == "*", parts[4] == "*"

    def matches(self, t):
        lt = time.localtime(t)
        if lt.tm_min not in self.minute or lt.tm_hour not in self.hour or lt.tm_mon not in self.month:
            return False
        dom_ok, dow_ok = lt.tm_mday in self.dom, (lt.tm_wday + 1) % 7 in self.dow
        if self.dom_any or self.dow_any:
            return dom_ok and dow_ok
        return dom_ok or dow_ok

    def prev(self, now, horizon_days=400):
        """Latest fire time <= now (epoch seconds, on a minute boundary), or None within the horizon."""
        t = int(now) - int(now) % 60
        end = t - horizon_days * 86400
        while t >= end:
            lt = time.localtime(t)
            if lt.tm_mon not in self.month or not self._day_ok(lt):
                t -= lt.tm_hour * 3600 + lt.tm_min * 60 + 60   # jump to the previous day's 23:59
                continue
            if lt.tm_hour not in self.hour:
                t -= lt.tm_min * 60 + 60                      # previous hour's :59
                continue
            if lt.tm_min in self.minute:
                return t
            t -= 60
        return None

    def next(self, now, horizon_days=400):
        t = int(now) - int(now) % 60 + 60
        end = t + horizon_days * 86400
        while t <= end:
            if self.matches(t):
                return t
            t += 60
        return None

    def _day_ok(self, lt):
        dom_ok, dow_ok = lt.tm_mday in self.dom, (lt.tm_wday + 1) % 7 in self.dow
        if self.dom_any or self.dow_any:
            return dom_ok and dow_ok
        return dom_ok or dow_ok

    def interval(self, now=None):
        """Typical seconds between fires (the smallest gap among the next few), for staleness thresholds."""
        t = self.next(now or time.time())
        gaps = []
        for _ in range(6):
            n = self.next(t)
            if n is None:
                break
            gaps.append(n - t)
            t = n
        return min(gaps) if gaps else 0


def parse_duration(s):
    """'90s' '30m' '2h' '7d' or a number of seconds -> seconds."""
    if s is None or s == "":
        return 0
    if isinstance(s, (int, float)):
        return int(s)
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    s = str(s).strip()
    if s[-1] in units:
        return int(float(s[:-1]) * units[s[-1]])
    return int(s)
