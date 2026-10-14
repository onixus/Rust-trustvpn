import contextlib,hashlib,io,pathlib,tarfile,tempfile,unittest
from unittest.mock import patch
import tools

class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name);self.archive=self.root/'download.tar.gz'
    def archive_with(self,members=None):
        with tarfile.open(self.archive,'w:gz') as tar:
            for name,kind,body in members or [('nested/trivy','file',b'good-tool')]:
                item=tarfile.TarInfo(name);item.mode=0o755
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

if __name__=='__main__':unittest.main()
