"""Download official pinned tools into the job workspace, never globally."""
import hashlib,json,pathlib,platform,subprocess,tarfile,sys,os,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def install(name):
    key=platform.system()+'-'+platform.machine()
    item=json.loads((ROOT/'ci/tools.lock.json').read_text())[name][key]
    directory=ROOT/'.ci-tools'/name;directory.mkdir(parents=True,exist_ok=True)
    archive=directory/'download.tar.gz'
    cache=pathlib.Path(os.environ['RTRUST_TOOL_CACHE'])/item['sha256'] if os.environ.get('RTRUST_TOOL_CACHE') else None
    # Jobs share the cache and run this concurrently: read it once, and treat a
    # file that another job is replacing as a miss.
    cached=None
    if cache:
        try:cached=cache.read_bytes()
        except OSError:pass
    cached=cached if cached is not None and hashlib.sha256(cached).hexdigest()==item['sha256'] else None
    if cached is not None:archive.write_bytes(cached)
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest()!=item['sha256']:
        subprocess.run(['curl','-fLsS','--connect-timeout','15','--max-time','120','--retry','2',item['url'],'-o',str(archive)],check=True)
    # Publish only what the cache lacks. Rewriting a valid entry on every run made
    # it vanish for a moment under a concurrent job (rename is not atomic on VirtioFS).
    if cache and cached is None and hashlib.sha256(archive.read_bytes()).hexdigest()==item['sha256']:
        cache.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cache.parent,delete=False) as f:
            temporary=pathlib.Path(f.name);f.write(archive.read_bytes())
        temporary.replace(cache)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=item['sha256']:raise RuntimeError('Tool checksum mismatch: '+name)
    with tarfile.open(archive) as tar:tar.extractall(directory,filter='data')
    executable='trusttunnel_endpoint' if name=='endpoint' else name
    return str(next(p for p in directory.rglob(executable) if p.is_file()))
if __name__=='__main__': print(install(sys.argv[1]))
