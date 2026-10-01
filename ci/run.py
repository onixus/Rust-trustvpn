"""Preserve complete stage logs and emit JUnit even when a command fails."""
import os,pathlib,subprocess,sys,time,xml.etree.ElementTree as E
sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
name=sys.argv[1];reports=pathlib.Path('reports');reports.mkdir(exist_ok=True)
start=time.monotonic();code=1
with (reports/(name+'.log')).open('w',encoding='utf-8') as log:
    try:
        process=subprocess.Popen(sys.argv[2:],env=dict(os.environ,PYTHONIOENCODING="utf-8",PYTHONUTF8="1"),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace')
        for line in process.stdout: print(line,end='',flush=True);log.write(line)
        code=process.wait()
    except Exception as error:log.write(str(error));print(error)
root=E.Element('testsuite',name=name,tests='1',failures=str(int(code!=0)),time=str(time.monotonic()-start))
case=E.SubElement(root,'testcase',name=name,classname='rtrust.ci')
if code:E.SubElement(case,'failure',message=f'Exit code {code}; see {name}.log')
E.ElementTree(root).write(reports/(name+'.xml'),encoding='utf-8',xml_declaration=True)
sys.exit(code)
