import pathlib,subprocess,sys
from tools import install
pathlib.Path('reports').mkdir(exist_ok=True)
codes=[]
codes.append(subprocess.call([sys.executable,str(pathlib.Path(__file__).with_name('test_release_acceptance.py'))]))
codes.append(subprocess.call([install('gitleaks'),'dir','.', '--config','.gitleaks.toml','--redact','--report-format','json','--report-path','reports/gitleaks.json','--exit-code','1']))
codes.append(subprocess.call([install('trivy'),'fs','--scanners','vuln,misconfig','--severity','HIGH,CRITICAL','--exit-code','1','--skip-dirs','.ci-tools,target,dist,reports','--format','json','--output','reports/trivy.json','.']))
raise SystemExit(int(any(codes)))
