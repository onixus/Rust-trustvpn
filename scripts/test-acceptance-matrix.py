#!/usr/bin/env python3
"""Regression checks for evidence gating; synthetic files are not VPN acceptance."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('acceptance_matrix', Path(__file__).with_name('acceptance-matrix.py'))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
SHA = 'a' * 40


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root / 'synthetic-package.bin'
        self.artifact.write_bytes(b'not an installable package: test fixture')
        self.evidence = self.root / 'synthetic-result.json'
        self.evidence.write_text('{"unit_fixture":true}')
        self.ledger = self.root / 'acceptance.json'
        self.assertEqual(self.invoke('init', '--output', str(self.ledger), '--commit', SHA,
                                     '--version', 'unit-fixture', '--platform', 'unit-test',
                                     '--device', 'synthetic', '--os-version', 'synthetic',
                                     '--owner', 'test-runner', '--artifact', str(self.artifact),
                                     '--protocol', 'h2', '--protocol', 'h3',
                                     '--mode', 'ordinary', '--mode', 'always_on',
                                     '--recovery-seconds', '30', '--max-rss-mib', '100',
                                     '--max-cpu-percent', '10', '--max-battery-percent-hour', '5'), 0)

    def invoke(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return matrix.main(args)

    def verify(self, commit=SHA):
        return self.invoke('verify', '--ledger', str(self.ledger), '--commit', commit, '--require-passed')

    def record(self, case, status, evidence=True):
        args = ['record', '--ledger', str(self.ledger), '--commit', SHA, '--case', case,
                '--status', status, '--owner', 'reviewer', '--reason', 'Synthetic test only']
        if evidence:
            args.extend(['--evidence', str(self.evidence)])
        return self.invoke(*args)

    def test_new_matrix_is_not_accepted(self):
        data = json.loads(self.ledger.read_text())
        self.assertEqual(len(data['results']), len(matrix.PACKAGE) + 4 * len(matrix.NETWORK))
        self.assertTrue(all(row['status'] == 'not_run' for row in data['results'].values()))
        self.assertEqual(self.verify(), 1)

    def test_complete_passes_and_failure_unsupported_deny_acceptance(self):
        for case in json.loads(self.ledger.read_text())['results']:
            self.assertEqual(self.record(case, 'passed'), 0)
        self.assertEqual(self.verify(), 0)
        self.assertEqual(self.record('publisher_signature', 'unsupported', False), 0)
        self.assertEqual(self.verify(), 1)
        self.assertEqual(self.record('publisher_signature', 'failed'), 0)
        self.assertEqual(self.verify(), 1)

    def test_no_evidence_no_pass(self):
        self.assertEqual(self.record('clean_install', 'passed', False), 2)
        self.assertEqual(self.record('clean_install', 'failed', False), 2)
        self.assertEqual(self.verify(), 1)

    def test_exact_source_commit_required(self):
        self.assertEqual(self.verify('b' * 40), 2)

    def test_artifact_tampering_is_rejected(self):
        self.artifact.write_bytes(b'different package')
        self.assertEqual(self.verify(), 2)
        self.assertEqual(self.record('clean_install', 'passed'), 2)

    def test_evidence_tampering_is_rejected(self):
        self.assertEqual(self.record('clean_install', 'passed'), 0)
        self.evidence.write_text('changed result')
        self.assertEqual(self.verify(), 2)

    def test_missing_evidence_is_rejected(self):
        self.assertEqual(self.record('clean_install', 'passed'), 0)
        self.evidence.unlink()
        self.assertEqual(self.verify(), 2)

    def test_deleted_case_cannot_make_matrix_complete(self):
        data = json.loads(self.ledger.read_text())
        del data['results']['h3/always_on/forbidden_egress']
        self.ledger.write_text(json.dumps(data))
        self.assertEqual(self.verify(), 2)

    def test_invalid_or_deleted_budget_is_rejected(self):
        original = json.loads(self.ledger.read_text())
        for budget in (float('nan'), float('inf'), -1, 0):
            data = json.loads(json.dumps(original))
            data['criteria']['recovery_seconds'] = budget
            self.ledger.write_text(json.dumps(data))
            self.assertEqual(self.verify(), 2)
        data = original
        del data['criteria']['recovery_seconds']
        self.ledger.write_text(json.dumps(data))
        self.assertEqual(self.verify(), 2)

    def test_scope_collision_and_empty_result_do_not_pass(self):
        data = json.loads(self.ledger.read_text())
        data['protocols'] = ['h2', 'h2/selected']
        self.ledger.write_text(json.dumps(data))
        self.assertEqual(self.verify(), 2)
        before = self.ledger.read_bytes()
        self.assertEqual(self.invoke('record', '--ledger', str(self.ledger), '--commit', SHA,
                                     '--case', 'clean_install', '--status', 'unsupported',
                                     '--owner', 'reviewer', '--reason', ' '), 2)
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_init_never_overwrites_reviewed_ledger(self):
        before = self.ledger.read_bytes()
        self.assertEqual(self.invoke('init', '--output', str(self.ledger), '--commit', SHA,
                                     '--version', 'unit-fixture', '--platform', 'unit-test',
                                     '--device', 'synthetic', '--os-version', 'synthetic',
                                     '--owner', 'test-runner', '--artifact', str(self.artifact),
                                     '--protocol', 'h2', '--mode', 'ordinary',
                                     '--recovery-seconds', '30', '--max-rss-mib', '100',
                                     '--max-cpu-percent', '10', '--max-battery-percent-hour', '5'), 2)
        self.assertEqual(self.ledger.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
