"""批处理完整性、只读保证与“来源不变但依据换了要保留切口”的测试。"""

import hashlib
import json
import os
import tempfile
import unittest

from tests.test_nat_semantics import EXP, OBS, SESS, Scene, edge
from ipfix_offline.nat_correlate import NatCorrelator, load_requests


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class ReadOnlyAndCleanupTests(unittest.TestCase):
    CFG = {"realms": ["H", "W"], "links": [["H", "W"]], "origins": ["H"],
           "observations": [{"exporter": EXP, "transport_session": SESS,
                             "observation_domain_id": OBS, "realm": "W"}]}

    def setUp(self):
        self.scene = Scene(self.CFG)
        self.scene.dir = tempfile.mkdtemp(prefix="nat_integrity_")
        self.scene.db = os.path.join(self.scene.dir, "store.db")
        self.scene.config_path = os.path.join(self.scene.dir, "topology.json")
        with open(self.scene.config_path, "w") as fh:
            json.dump(self.scene.config, fh)
        self.A = [6, "10.0.0.1", 1000, "198.51.100.1", 80]
        self.X = [6, "10.0.9.1", 2000, "198.51.100.1", 80]
        self.Z = [6, "198.51.100.1", 80, "203.0.113.1", 5000]
        self.flow_id = self.scene.ingest_flow(self.Z, 0, 10)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.scene.dir, ignore_errors=True)
        self.scene.cleanup()

    def _request(self):
        path = os.path.join(self.scene.dir, "req.jsonl")
        with open(path, "w") as fh:
            fh.write(json.dumps({"request_id": "r",
                                 "flow_id": self.flow_id}) + "\n")
        return path

    def test_database_is_not_modified(self):
        log = self.scene.write_logs("logs.jsonl", [
            edge("A-W", "H", "W", self.A, self.Z, 0, 10)])
        before = sha256(self.scene.db)
        mtime = os.stat(self.scene.db).st_mtime_ns
        with NatCorrelator(self.scene.db, self.scene.config_path, [log],
                           self.scene.dir, measure_memory=False) as nc:
            nc.correlate_requests(load_requests(self._request()))
        self.assertEqual(sha256(self.scene.db), before)
        self.assertEqual(os.stat(self.scene.db).st_mtime_ns, mtime)

    def test_only_own_temp_files_are_removed(self):
        keep = os.path.join(self.scene.dir, "operator-notes.txt")
        with open(keep, "w") as fh:
            fh.write("do not delete\n")
        log = self.scene.write_logs("logs.jsonl", [])
        with NatCorrelator(self.scene.db, self.scene.config_path, [log],
                           self.scene.dir, measure_memory=False) as nc:
            nc.correlate_requests(load_requests(self._request()))
            # 索引目录存在且在本工作目录下
            self.assertTrue(nc.index_path.startswith(self.scene.dir))
        self.assertTrue(os.path.exists(keep))
        leftovers = [name for name in os.listdir(self.scene.dir)
                     if name.startswith(".ipfix_nat_")]
        self.assertEqual(leftovers, [])

    def test_keep_index_keeps_only_own_directory(self):
        log = self.scene.write_logs("logs.jsonl", [])
        with NatCorrelator(self.scene.db, self.scene.config_path, [log],
                           self.scene.dir, measure_memory=False,
                           keep_index=True) as nc:
            index_path = nc.index_path
        self.assertTrue(os.path.isfile(index_path))
        import shutil
        shutil.rmtree(os.path.dirname(index_path), ignore_errors=True)


class EvidenceChangeCutsFragmentTests(unittest.TestCase):
    CFG = {"realms": ["H", "W"], "links": [["H", "W"]], "origins": ["H"],
           "observations": [{"exporter": EXP, "transport_session": SESS,
                             "observation_domain_id": OBS, "realm": "W"}]}

    def test_same_origin_different_mapping_is_a_new_fragment(self):
        scene = Scene(self.CFG)
        try:
            A = [6, "10.0.0.1", 1000, "198.51.100.1", 80]
            X = [6, "10.0.9.1", 2000, "198.51.100.1", 80]
            Z = [6, "198.51.100.1", 80, "203.0.113.1", 5000]
            flow_id = scene.ingest_flow(Z, 0, 10)
            logs = [
                edge("hop-1", "H", "W", A, Z, 0, 5),
                edge("hop-2", "H", "W", A, Z, 5, 10),
            ]
            path = scene.write_logs("logs.jsonl", logs)
            req = scene.write_requests(
                [{"request_id": "r", "flow_id": flow_id}])
            with NatCorrelator(scene.db, scene.config_path, [path],
                               scene.dir, measure_memory=False) as nc:
                report = nc.correlate_requests(load_requests(req))
            fragments = report["requests"][0]["fragments"]
            self.assertEqual([(f["start_ms"], f["end_ms"], f["status"])
                              for f in fragments],
                             [(0, 5, "unique"), (5, 10, "unique")])
            # 同一来源，但支撑日志换了：必须保留切口
            for fragment in fragments:
                self.assertEqual(len(fragment["origins"]), 1)
            self.assertEqual([e["mapping_id"] for e in fragments[0]["graph"]["edges"]],
                             ["hop-1"])
            self.assertEqual([e["mapping_id"] for e in fragments[1]["graph"]["edges"]],
                             ["hop-2"])
        finally:
            scene.cleanup()


if __name__ == "__main__":
    unittest.main()
