"""Download official pinned tools into the job workspace, never globally."""
import hashlib,json,pathlib,platform,subprocess,tarfile,sys,os,tempfile,shutil,stat,time,contextlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
def _digest(stream):
    digest=hashlib.sha256()
    for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()

def _matches(path,size,digest):
    try:
        metadata=path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode&0o111 or metadata.st_size!=size:return False
        with path.open('rb') as content:return _digest(content)==digest
    except FileNotFoundError:return False

@contextlib.contextmanager
def _publication_lock(directory,timeout=20):
    # OS advisory locks are released on process exit, including a crashed job.
    with (directory/'.publish.lock').open('a+b') as lock:
        if os.name=='nt':
            import msvcrt
            lock.seek(0,os.SEEK_END)
            if not lock.tell():lock.write(b'0');lock.flush()
            def acquire():
                lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
            def release():
                lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1)
        else:
            import fcntl
            def acquire():fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            def release():fcntl.flock(lock.fileno(),fcntl.LOCK_UN)
        until=time.monotonic()+timeout
        while True:
            try:acquire();break
            except (BlockingIOError,PermissionError):
                remaining=until-time.monotonic()
                if remaining<=0:raise TimeoutError('Tool publication lock timeout')
                time.sleep(min(.05,remaining))
        try:yield
        finally:release()

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
            # One stable executable per pinned archive. Never prune another
            # version or a path already handed to a consumer.
            published=directory/('verified-'+sha256)
            published.mkdir(exist_ok=True)
            if published.is_symlink():raise RuntimeError('Unsafe tool output: '+name)
            output=published/executable
            with _publication_lock(published):
                if _matches(output,member.size,expected):return str(output)
                for attempt in range(1,attempts+1):
                    staging=pathlib.Path(tempfile.mkdtemp(prefix='extract-',dir=directory))
                    try:
                        tar.extractall(staging,members=members,filter='data')
                        result=staging.joinpath(*pathlib.PurePosixPath(member.name).parts)
                        if _matches(result,member.size,expected):
                            # Replace only this owned binary. Open readers retain
                            # their inode; Windows busy-file errors fail closed.
                            result.replace(output)
                            if _matches(output,member.size,expected):return str(output)
                        print(f'Tool extraction validation failed: {name} attempt {attempt}',file=sys.stderr,flush=True)
                    finally:
                        shutil.rmtree(staging)
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
