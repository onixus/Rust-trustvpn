"""Download official pinned tools into the job workspace, never globally."""
import hashlib,json,pathlib,platform,subprocess,tarfile,sys,os,tempfile,shutil,stat
ROOT=pathlib.Path(__file__).resolve().parents[1]
def _digest(stream):
    digest=hashlib.sha256()
    for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()

def extract_verified(archive,directory,name,sha256,attempts=3):
    """Return only a fresh executable matching the pinned archive content."""
    with archive.open('rb') as source:
        if _digest(source)!=sha256:raise RuntimeError('Tool checksum mismatch: '+name)
        source.seek(0)
        with tarfile.open(fileobj=source) as tar:
            members=tar.getmembers();seen=set();candidates=[]
            executable='trusttunnel_endpoint' if name=='endpoint' else name
            for member in members:
                path=pathlib.PurePosixPath(member.name)
                if (path.is_absolute() or '..' in path.parts or '\\' in member.name
                        or ':' in member.name or not path.parts
                        or not (member.isfile() or member.isdir())):
                    raise RuntimeError('Unsafe tool archive: '+name)
                normalized=str(path)
                if normalized in seen:raise RuntimeError('Duplicate tool archive member: '+name)
                seen.add(normalized)
                if path.name==executable and member.isfile() and member.mode&0o111:candidates.append(member)
            if len(candidates)!=1:raise RuntimeError('Ambiguous tool executable: '+name)
            member=candidates[0]
            with tar.extractfile(member) as content:expected=_digest(content)
            for attempt in range(1,attempts+1):
                staging=pathlib.Path(tempfile.mkdtemp(prefix='extract-',dir=directory));keep=False
                try:
                    tar.extractall(staging,members=members,filter='data')
                    result=staging.joinpath(*pathlib.PurePosixPath(member.name).parts)
                    metadata=result.lstat()
                    if stat.S_ISREG(metadata.st_mode) and metadata.st_mode&0o111 and metadata.st_size==member.size:
                        with result.open('rb') as content:valid=_digest(content)==expected
                        if valid:
                            keep=True
                            return str(result)
                    print(f'Tool extraction validation failed: {name} attempt {attempt}',file=sys.stderr,flush=True)
                finally:
                    if not keep:shutil.rmtree(staging)
            raise RuntimeError('Tool extraction validation exhausted: '+name)

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
    return extract_verified(archive,directory,name,item['sha256'])
if __name__=='__main__': print(install(sys.argv[1]))
