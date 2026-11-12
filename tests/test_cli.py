import sqlite3
import tempfile
import unittest
from pathlib import Path
from pihole_report import cli


class CLISafetyTests(unittest.TestCase):
    def test_reject_production_outputs(self):
        with self.assertRaises(ValueError):
            cli.isolated_path(Path.home()/'pihole-reporter/memory/pihole-domain-review.md')

    def test_reject_parent_and_sync(self):
        for path in (cli.PROJECT, cli.PROJECT/'../live.sqlite', cli.PROJECT/'OneDrive/x'):
            with self.assertRaises(ValueError):
                cli.isolated_path(path)

    def test_reject_symlink_escape(self):
        with tempfile.TemporaryDirectory(dir=cli.PROJECT) as d:
            (Path(d)/'outside').symlink_to('/tmp', target_is_directory=True)
            with self.assertRaises(ValueError):
                cli.isolated_path(Path(d)/'outside/live.sqlite')

    def test_database_is_query_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'source.sqlite'
            with sqlite3.connect(p) as c:
                c.execute('CREATE TABLE t(n)')
            with cli.read_database(p) as c:
                with self.assertRaises(sqlite3.OperationalError):
                    c.execute('INSERT INTO t VALUES(1)')

    def test_atomic_output_and_backup(self):
        with tempfile.TemporaryDirectory(dir=cli.PROJECT) as d:
            p = Path(d)/'source.sqlite'
            with sqlite3.connect(p) as c:
                c.execute('CREATE TABLE t(n)')
                c.execute('INSERT INTO t VALUES(7)')
            cli.copy_database(p, Path(d)/'copy.sqlite')
            with cli.read_database(Path(d)/'copy.sqlite') as c:
                self.assertEqual(c.execute('SELECT n FROM t').fetchone()[0],7)
            with self.assertRaises(FileExistsError):
                cli.copy_database(p, Path(d)/'copy.sqlite')
            cli.atomic_text(Path(d)/'report.md','safe')
            self.assertEqual((Path(d)/'report.md').read_text(),'safe')

class LiveCommandTests(unittest.TestCase):
    def test_network_flag_required_before_any_secret_read(self):
        from contextlib import redirect_stderr
        import io
        from unittest.mock import patch
        with patch('pihole_report.delivery.read_secret', side_effect=AssertionError('must not read')), patch('pihole_report.runlog.write_log'), patch('pihole_report.runlog.prune_logs', return_value={}):
            with redirect_stderr(io.StringIO()):
                status = cli.main(['run-shadow','--root',str(cli.PROJECT/'.validation/nonexistent')])
        self.assertEqual(status,1)

if __name__ == '__main__':
    unittest.main()
