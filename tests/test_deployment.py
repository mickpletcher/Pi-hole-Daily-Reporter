"""Portable local configuration validation with synthetic files only."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from pihole_report import deployment as d

class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name).resolve();self.config=self.root/'deployment.json'
        self.value=d.example_deployment(self.root);self.value['enabled']=True
        self.patch=patch.multiple(d,PROJECT=self.root,DEPLOYMENT=self.config);self.patch.start();self.addCleanup(self.patch.stop)
    def save(self):self.config.write_text(json.dumps(self.value));self.config.chmod(0o600)
    def test_explicit_valid_and_no_environment_override(self):
        self.save()
        with patch.dict('os.environ',{'PIHOLE_HOST':'evil.invalid','SMTP_RECIPIENT':'other@example.invalid'}):
            self.assertEqual(d.load_deployment(),self.value)
    def test_disabled_missing_world_readable_and_unknown_fields(self):
        with self.assertRaises(FileNotFoundError):d.load_deployment()
        self.value['enabled']=False;self.save()
        with self.assertRaises(ValueError):d.load_deployment()
        self.value['enabled']=True;self.save();self.config.chmod(0o644)
        with self.assertRaises(ValueError):d.load_deployment()
        self.value['extra']='invalid';self.save()
        with self.assertRaises(ValueError):d.load_deployment()
    def test_tls_and_scope_mismatch(self):
        self.value['scope']['pihole_base']='http://pihole.example.invalid';self.save()
        with self.assertRaises(ValueError):d.load_deployment()
        self.value=d.example_deployment(self.root);self.value['enabled']=True
        self.value['scheduler']['database']='/different/history.sqlite';self.save()
        with self.assertRaises(ValueError):d.load_deployment()
    def test_symlink_config_refused(self):
        self.save();other=self.root/'actual.json';self.config.rename(other);self.config.symlink_to(other)
        with self.assertRaises(ValueError):d.load_deployment()

if __name__=='__main__':unittest.main()
