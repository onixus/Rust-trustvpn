"""Create/update this job using an existing local Jenkins API token; never log it."""
import argparse,base64,pathlib,urllib.error,urllib.parse,urllib.request,xml.etree.ElementTree as E
p=argparse.ArgumentParser();p.add_argument('--url',default='http://localhost:8081');p.add_argument('--user',default='admin');p.add_argument('--token-file',type=pathlib.Path,required=True);p.add_argument('--build',action='store_true');args=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
def request(path,data=None,read=False):
    auth=base64.b64encode((args.user+':'+args.token_file.read_text().strip()).encode()).decode()
    req=urllib.request.Request(args.url.rstrip('/')+'/'+path,data=data,headers={'Authorization':'Basic '+auth,'Content-Type':'application/xml'})
    with urllib.request.urlopen(req,timeout=30) as response:return response.read() if read else response.status
job=E.Element('flow-definition');E.SubElement(job,'description').text='R-TrustTunnel native macOS/Windows CI: security, unit, smoke, official endpoint E2E and native release builds.'
d=E.SubElement(job,'definition',{'class':'org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition'});E.SubElement(d,'script').text=(root/'Jenkinsfile').read_text();E.SubElement(d,'sandbox').text='true';E.SubElement(job,'disabled').text='false'
try:
    existing=E.fromstring(request('job/rtrust-native/config.xml',read=True));exists=True
    # Preserve job properties (especially disableConcurrentBuilds), history and
    # authorization settings while updating the pipeline definition.
    old=existing.find('definition')
    if old is not None:existing.remove(old)
    existing.append(d)
    job=existing
except urllib.error.HTTPError as error:
    if error.code!=404:raise
    exists=False
request('job/rtrust-native/config.xml' if exists else 'createItem?name=rtrust-native',E.tostring(job,encoding='utf-8'))
if args.build:request('job/rtrust-native/buildWithParameters?WINDOWS_SYSTEM_E2E=false',b'')
print(args.url.rstrip('/')+'/job/rtrust-native/')
