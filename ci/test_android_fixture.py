"""The Android fixture certificate must already be valid on a lagging emulator clock."""
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch
import android_fixture as fixture

class CertificateTests(unittest.TestCase):
    def test_validity_tolerates_device_clock_skew_in_both_directions(self):
        issued = datetime(2026, 10, 12, 20, 26, 20, tzinfo=timezone.utc)
        with patch.object(fixture.subprocess, 'run') as run:
            fixture.certificate('/fixture', issued)
        args = run.call_args.args[0]
        self.assertNotIn('-days', args)
        parse = lambda flag: datetime.strptime(args[args.index(flag) + 1], '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
        self.assertLessEqual(parse('-not_before'), issued - timedelta(hours=1))
        self.assertGreaterEqual(parse('-not_after'), issued + timedelta(hours=1))
        self.assertIn('basicConstraints=critical,CA:FALSE', args)
        self.assertEqual(run.call_args.kwargs['cwd'], '/fixture')

if __name__ == '__main__':
    unittest.main()
