"""Run synthetic tests in a clean home with network-denying Python workers."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='reporter-ci-') as home:
        # Never inherit deployment/account configuration. All output is ephemeral.
        env = {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT', 'WINDIR',
               'LANG', 'LC_ALL') if key in os.environ}
        env.update(HOME=home, USERPROFILE=home, TMPDIR=home, TEMP=home, TMP=home,
                   PYTHONDONTWRITEBYTECODE='1',
                   PYTHONPATH=os.pathsep.join((str(ROOT / 'scripts' / 'ci'), str(ROOT))))
        probe = subprocess.run([sys.executable, '-c',
            "import socket\ntry: socket.create_connection(('example.invalid',443))\n"
            "except RuntimeError: pass\nelse: raise SystemExit('network guard missing')"],
            cwd=ROOT, env=env)
        if probe.returncode:
            return probe.returncode
        return subprocess.call([sys.executable, '-m', 'unittest', 'discover',
                                '-s', 'tests', '-v'], cwd=ROOT, env=env)


if __name__ == '__main__':
    raise SystemExit(main())
