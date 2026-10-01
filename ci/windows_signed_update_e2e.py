"""Explicit installed-client maintenance; never run by unattended CI.
Run in the authorized user's interactive elevated session with a sequence-N test
runner, genuine signed N/N+1 packages and maintenance_fixture begin completed.
Injects a failed health check, observes real rollback, then performs a real upgrade.
"""
import argparse, json, os, pathlib, subprocess
p=argparse.ArgumentParser()
p.add_argument('--allow-existing-installation',action='store_true')
p.add_argument('--transaction',type=pathlib.Path,required=True)
p.add_argument('--runner',type=pathlib.Path,required=True)
p.add_argument('--fixture',type=pathlib.Path,required=True)
p.add_argument('--backup',type=pathlib.Path,required=True)
a=p.parse_args()
assert a.allow_existing_installation,'Explicit maintenance authorization is required'
assert os.name=='nt'
env=dict(os.environ,RTRUST_UPDATE_TEST_TRANSACTION=str(a.transaction))
result=subprocess.run([str(a.runner),'--ignored','--exact',
 'windows::tests::real_signed_upgrade_and_health_failure_rollback','--nocapture'],
 env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=480)
(a.transaction/'test-output.log').write_bytes(result.stdout)
print(result.stdout.decode('utf-8',errors='replace'))
# A missing test must not be counted as a successful rollback.
assert result.returncode==0 and b'1 passed' in result.stdout,'Signed update/rollback failed; backup and logs retained'
subprocess.run([str(a.fixture),'end',str(a.backup)],check=True,timeout=30)
(a.transaction/'e2e-result.json').write_text(json.dumps(dict(result='PASS',
 checks=['signed upgrade','injected unhealthy version','real signed rollback',
 'rollback launch smoke','successful retry','encrypted profile retention']),indent=2))
print('PASS real signed update, rollback and encrypted profile retention')
