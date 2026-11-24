"""Metric sinks and spools: text parsing, remote-write 1.0 encoding (decoded back), snappy framing, textfile atomicity,
secret-file permissions, exec spool round trip."""
import os
import shutil
import stat
import struct
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT]
from adapters import sinks, spool  # noqa: E402


def varint(b, i):
    n = shift = 0
    while True:
        x = b[i]
        i += 1
        n |= (x & 0x7F) << shift
        shift += 7
        if not x & 0x80:
            return n, i


def fields(b):
    i, out = 0, []
    while i < len(b):
        key, i = varint(b, i)
        f, wt = key >> 3, key & 7
        if wt == 2:
            n, i = varint(b, i)
            out.append((f, b[i:i + n]))
            i += n
        elif wt == 1:
            out.append((f, struct.unpack("<d", b[i:i + 8])[0]))
            i += 8
        elif wt == 0:
            v, i = varint(b, i)
            out.append((f, v))
    return out


def unsnappy(b):
    n, i = varint(b, 0)
    out = bytearray()
    while i < len(b):
        tag = b[i]
        i += 1
        assert tag & 3 == 0, "only literals expected"
        ln = tag >> 2
        if ln == 60:
            ln, i = b[i], i + 1
        elif ln == 61:
            ln, i = struct.unpack("<H", b[i:i + 2])[0], i + 2
        ln += 1
        out += b[i:i + ln]
        i += ln
    assert len(out) == n
    return bytes(out)


class RemoteWrite(unittest.TestCase):
    TEXT = '# HELP a x\n# TYPE a gauge\na{x="1",y="q\\"z"} 3.5\nb 7\n'

    def test_parse(self):
        self.assertEqual(sinks.parse_text(self.TEXT), [("a", {"x": "1", "y": 'q"z'}, 3.5), ("b", {}, 7.0)])
        with self.assertRaises(ValueError):
            sinks.parse_text("not a metric line at all {")

    def test_encode_roundtrip(self):
        body = sinks.encode_write_request(sinks.parse_text(self.TEXT), 1700000000123)
        series = [fields(v) for f, v in fields(body)]
        self.assertEqual(len(series), 2)
        labels = [dict((dict(fields(v))[1].decode(), dict(fields(v))[2].decode()) for f, v in s if f == 1) for s in series]
        self.assertEqual(labels[0], {"__name__": "a", "x": "1", "y": 'q"z'})
        sample = dict(fields([v for f, v in series[0] if f == 2][0]))
        self.assertEqual((sample[1], sample[2]), (3.5, 1700000000123))
        names = [k for f, v in series[0] if f == 1 for k in [dict(fields(v))[1]]]
        self.assertEqual(names, sorted(names), "labels must be sorted by name")

    def test_snappy_literals(self):
        for n in (0, 1, 59, 60, 255, 256, 70000, 200000):
            data = os.urandom(n)
            self.assertEqual(unsnappy(sinks.snappy_literal(data)), data)


class Files(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_textfile_atomic(self):
        p = os.path.join(self.d, "x", "m.prom")
        sinks.textfile({"path": p}, "a 1\n")
        sinks.textfile({"path": p, "exec": {"type": "local"}}, "a 2\n")
        self.assertEqual(open(p).read(), "a 2\n")
        self.assertEqual(os.listdir(os.path.dirname(p)), ["m.prom"])

    def test_secret_file_must_be_private(self):
        p = os.path.join(self.d, "token")
        open(p, "w").write("s3cret\n")
        os.chmod(p, 0o644)
        with self.assertRaises(PermissionError):
            sinks.read_secret_file(p)
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
        self.assertEqual(sinks.read_secret_file(p), "s3cret")

    def test_spool_roundtrip(self):
        sp = spool.spool({"type": "local", "dir": os.path.join(self.d, "out")})
        self.assertEqual(sp.list(), [])
        sp.put("b.json", "{}")
        sp.put("a.json", '{"x": 1}')
        self.assertEqual(sp.list(), ["a.json", "b.json"])
        self.assertEqual(sp.get("a.json"), '{"x": 1}')
        sp.ack("a.json")
        self.assertEqual(sp.list(), ["b.json"])
        self.assertTrue(os.path.exists(os.path.join(self.d, "out", "sent", "a.json")))


if __name__ == "__main__":
    unittest.main()
