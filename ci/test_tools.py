import contextlib,hashlib,io,pathlib,tarfile,tempfile,unittest,json,platform,threading,concurrent.futures,os,stat,types
from unittest.mock import patch,Mock
import tools

class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name);self.archive=self.root/'download.tar.gz'
    def archive_with(self,members=None,mode=0o755):
        with tarfile.open(self.archive,'w:gz') as tar:
            for name,kind,body in members or [('nested/trivy','file',b'good-tool')]:
                item=tarfile.TarInfo(name);item.mode=mode
                if kind=='file':item.size=len(body);tar.addfile(item,io.BytesIO(body))
                else:item.type=tarfile.SYMTYPE;item.linkname=body;tar.addfile(item)
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()
    def extract(self,sha):return tools.extract_verified(self.archive,self.root,'trivy',sha)
    def test_same_size_corruption_retried_in_fresh_directory(self):
        sha=self.archive_with();original=tarfile.TarFile.extractall;stages=[]
        def corrupt(tar,path,**kwargs):
            stages.append(path);original(tar,path,**kwargs)
            if len(stages)==1:(path/'nested/trivy').write_bytes(b'evil-tool')
        with patch.object(tarfile.TarFile,'extractall',corrupt),contextlib.redirect_stderr(io.StringIO()) as logs:
            result=pathlib.Path(self.extract(sha))
        self.assertEqual(result.read_bytes(),b'good-tool');self.assertEqual(len(stages),2)
        self.assertNotEqual(stages[0],stages[1]);self.assertFalse(stages[0].exists())
        self.assertIn('trivy attempt 1',logs.getvalue())
    def test_persistent_corruption_exhausts_and_cleans(self):
        sha=self.archive_with();original=tarfile.TarFile.extractall;stages=[]
        def corrupt(tar,path,**kwargs):
            stages.append(path);original(tar,path,**kwargs);(path/'nested/trivy').write_bytes(b'evil-tool')
        with patch.object(tarfile.TarFile,'extractall',corrupt),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'exhausted'):self.extract(sha)
        self.assertEqual(len(stages),3);self.assertTrue(all(not p.exists() for p in stages))
    def test_bad_archive_checksum_never_extracts(self):
        self.archive_with()
        with patch.object(tarfile.TarFile,'extractall') as extract:
            with self.assertRaisesRegex(RuntimeError,'checksum'):self.extract('0'*64)
        extract.assert_not_called()
    def test_stale_executable_ignored(self):
        (self.root/'trivy').write_bytes(b'stale');sha=self.archive_with()
        result=pathlib.Path(self.extract(sha));self.assertEqual(result.read_bytes(),b'good-tool')
        self.assertNotEqual(result,self.root/'trivy')
    def test_unsafe_members_fail_before_extraction(self):
        for member in [('..//trivy','file',b'x'),('/trivy','file',b'x'),('link','symlink','trivy'),('C:/trivy','file',b'x'),('a\\trivy','file',b'x')]:
            with self.subTest(member=member[0]):
                sha=self.archive_with([('trivy','file',b'good'),member])
                with patch.object(tarfile.TarFile,'extractall') as extract:
                    with self.assertRaisesRegex(RuntimeError,'Unsafe'):self.extract(sha)
                extract.assert_not_called()
    def test_multiple_candidates_or_duplicates_fail(self):
        for names in [('a/trivy','b/trivy'),('trivy','trivy')]:
            sha=self.archive_with([(n,'file',b'tool') for n in names])
            with self.assertRaises(RuntimeError):self.extract(sha)
    def test_extraction_exception_cleans_stage(self):
        sha=self.archive_with()
        with patch.object(tarfile.TarFile,'extractall',side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):self.extract(sha)
        self.assertEqual(list(self.root.glob('extract-*')),[])

    def test_repeated_install_reuses_output_without_mutating_active_reader(self):
        sha=self.archive_with();directory=self.root/'.ci-tools/trivy';directory.mkdir(parents=True)
        (directory/'download.tar.gz').write_bytes(self.archive.read_bytes())
        (self.root/'ci').mkdir()
        (self.root/'ci/tools.lock.json').write_text(json.dumps({'trivy':{platform.system()+'-'+platform.machine():{'sha256':sha,'url':'synthetic-invalid'}}}))
        with patch.object(tools,'ROOT',self.root),patch.dict(os.environ,{'RTRUST_TOOL_CACHE':''}):
            output=pathlib.Path(tools.install('trivy'));metadata=output.stat()
            with output.open('rb') as reader,patch.object(tarfile.TarFile,'extractall') as extraction:
                for _ in range(5):self.assertEqual(tools.install('trivy'),str(output))
                self.assertEqual(reader.read(),b'good-tool');extraction.assert_not_called()
            self.assertEqual(output.stat().st_ino,metadata.st_ino)
            self.assertEqual(output.stat().st_mtime_ns,metadata.st_mtime_ns)
        self.assertEqual(list(directory.glob('extract-*')),[])
        self.assertEqual(len(list(directory.glob('verified-*'))),1)
    def test_corrupt_reused_output_repaired(self):
        sha=self.archive_with();output=pathlib.Path(self.extract(sha));output.write_bytes(b'evil-tool')
        self.assertEqual(self.extract(sha),str(output));self.assertEqual(output.read_bytes(),b'good-tool')
        self.assertEqual(list(self.root.glob('extract-*')),[])
    def test_post_publication_corruption_retries_and_exhausts(self):
        for persistent in [False,True]:
            with self.subTest(persistent=persistent):
                sha=self.archive_with();output=self.root/('verified-'+sha)/'trivy'
                output.unlink(missing_ok=True);original=pathlib.Path.replace;calls=[]
                def corrupt(path,destination):
                    result=original(path,destination);calls.append(destination)
                    if persistent or len(calls)==1:destination.write_bytes(b'evil-tool')
                    return result
                with patch.object(pathlib.Path,'replace',corrupt),contextlib.redirect_stderr(io.StringIO()):
                    if persistent:
                        with self.assertRaisesRegex(RuntimeError,'exhausted'):self.extract(sha)
                        self.assertEqual(len(calls),3)
                    else:
                        self.assertEqual(self.extract(sha),str(output));self.assertEqual(len(calls),2)
                        self.assertEqual(output.read_bytes(),b'good-tool')
                self.assertEqual(list(self.root.glob('extract-*')),[])
    def test_concurrent_installers_publish_once(self):
        sha=self.archive_with();original=tarfile.TarFile.extractall
        started=threading.Event();resume=threading.Event();calls=[]
        def delayed(tar,path,**kwargs):
            calls.append(path);started.set()
            if not resume.wait(3):raise TimeoutError('synthetic synchronization')
            original(tar,path,**kwargs)
        with patch.object(tarfile.TarFile,'extractall',delayed),concurrent.futures.ThreadPoolExecutor(2) as pool:
            first=pool.submit(self.extract,sha);self.assertTrue(started.wait(3))
            second=pool.submit(self.extract,sha);resume.set()
            self.assertEqual(first.result(timeout=3),second.result(timeout=3))
        self.assertEqual(len(calls),1);self.assertEqual(list(self.root.glob('extract-*')),[])
    def test_busy_file_replacement_fails_closed_and_cleans(self):
        sha=self.archive_with();output=pathlib.Path(self.extract(sha));output.write_bytes(b'evil-tool')
        with patch.object(pathlib.Path,'replace',side_effect=PermissionError('synthetic busy executable')):
            with self.assertRaises(PermissionError):self.extract(sha)
        self.assertEqual(output.read_bytes(),b'evil-tool');self.assertEqual(list(self.root.glob('extract-*')),[])

    def test_windows_stat_without_posix_execute_bits(self):
        body=b'good-tool';digest=hashlib.sha256(body).hexdigest()
        path=Mock()
        path.lstat.return_value=types.SimpleNamespace(st_mode=stat.S_IFREG|0o666,st_size=len(body))
        path.open.side_effect=lambda mode:io.BytesIO(body)
        self.assertTrue(tools._matches(path,len(body),digest,filesystem='nt'))
        self.assertFalse(tools._matches(path,len(body),digest,filesystem='posix'))
        self.assertFalse(tools._matches(path,len(body),'0'*64,filesystem='nt'))
        self.assertFalse(tools._matches(path,len(body)+1,digest,filesystem='nt'))
        path.lstat.return_value.st_mode=stat.S_IFLNK|0o777
        self.assertFalse(tools._matches(path,len(body),digest,filesystem='nt'))
    def test_archive_execute_mode_required_on_every_platform(self):
        sha=self.archive_with(mode=0o644)
        with patch.object(tarfile.TarFile,'extractall') as extraction:
            with self.assertRaisesRegex(RuntimeError,'Ambiguous tool executable'):self.extract(sha)
        extraction.assert_not_called()

if __name__=='__main__':unittest.main()
