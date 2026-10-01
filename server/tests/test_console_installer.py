"""Installer rollback with a temporary filesystem and fake Docker/systemd only."""
import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import json

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('console_installer',ROOT/'deploy/install-console.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class InstallerTests(unittest.TestCase):
    def test_failed_first_install_removes_new_agent_and_unit(self):
        self.failed_install(False)

    def test_agent_start_failure_preserves_existing_console(self):
        self.failed_install(True)

    def failed_install(self,existing):
        with tempfile.TemporaryDirectory(prefix='console-install-test-') as temp:
            root=Path(temp);dest=root/'console';data=root/'portal';data.mkdir()
            sqlite3.connect(data/'trusttunnel-web.db').close()
            nginx=root/'nginx.conf';nginx.write_text('server {\n    location / { proxy_pass upstream; }\n}\n')
            original=nginx.read_text();unit=root/'agent.service'
            if existing:
                dest.mkdir();unit.write_text('original-unit')
                for name in ('agent.py','root.pub','console.env'):(dest/name).write_text('original-'+name)
            current={'Image':'fixture-image','Config':{'Env':['SECRET_KEY=fixture-secret']},
                     'Mounts':[{'Source':str(data),'Destination':'/data'},{'Source':str(root),'Destination':'/certs'}]}
            def run(args):
                if args[:3]==['docker','inspect','trusttunnel-web']:return json.dumps([current])
                if (existing and args==['systemctl','restart','vpn-console-agent']) or (not existing and args[:3]==['docker','run','-d']):raise RuntimeError('fixture startup failed')
                return ''
            calls=[]
            def command(args,**kwargs):
                calls.append(args)
                if existing and args[:3]==['docker','inspect','vpn-console']:return subprocess.CompletedProcess(args,0,stdout='[{"Id":"previous-console"}]',stderr='')
                if existing and args[:2] in (['systemctl','is-active'],['systemctl','is-enabled']):return subprocess.CompletedProcess(args,0,stdout='',stderr='')
                return subprocess.CompletedProcess(args,1 if args[:3]==['docker','inspect','vpn-console'] or args[:2] in (['systemctl','is-active'],['systemctl','is-enabled']) else 0,stdout='',stderr='')
            with patch.object(installer,'DEST',dest),patch.object(installer,'BACK',dest/'backup'),patch.object(installer,'NGINX',nginx),patch.object(installer,'UNIT',unit),patch.object(installer,'run',side_effect=run),patch.object(installer.subprocess,'run',side_effect=command),patch.object(installer.os,'geteuid',return_value=0),patch.object(installer.os,'chown'),patch.object(installer.time,'sleep'):
                with self.assertRaisesRegex(RuntimeError,'fixture startup failed'):installer.main()
            self.assertEqual(nginx.read_text(),original)
            if existing:
                self.assertEqual(unit.read_text(),'original-unit')
                for name in ('agent.py','root.pub','console.env'):self.assertEqual((dest/name).read_text(),'original-'+name)
                self.assertNotIn(['docker','rm','-f','vpn-console'],calls)
                self.assertIn(['systemctl','start','vpn-console-agent'],calls)
                return
            self.assertFalse(unit.exists(),'Failed first install must not leave an enabled root service')
            self.assertIn(['systemctl','stop','vpn-console-agent'],calls)
            self.assertIn(['systemctl','disable','vpn-console-agent'],calls)
            for name in ('agent.py','root.pub','console.env'):self.assertFalse((dest/name).exists())

if __name__=='__main__':unittest.main(verbosity=2)
