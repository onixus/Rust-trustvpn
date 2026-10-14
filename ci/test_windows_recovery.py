import ast,pathlib,types,unittest
from windows_recovery import LEASE_BUSY,recover_after_crash

class RecoveryTests(unittest.TestCase):
    def run_recovery(self,responses,timeout=1,guard=None):
        self.now=0;self.pipes=[];self.guards=[]
        test=self
        class Pipe:
            def __init__(self):self.closed=False;test.pipes.append(self)
            def request(self,command,deadline):
                test.assertEqual(command,{'op':'Recover'});test.assertEqual(deadline,timeout)
                value=responses.pop(0) if len(responses)>1 else responses[0]
                if isinstance(value,Exception):raise value
                return value
            def close(self):self.closed=True
        def sleep(delay):self.now+=delay
        def observe():
            self.guards.append(self.now)
            if guard:guard()
        try:return recover_after_crash(Pipe,observe,timeout=timeout,interval=.2,clock=lambda:self.now,sleep=sleep)
        finally:self.assertTrue(all(p.closed for p in self.pipes))
    def test_busy_then_idle_fresh_pipe_and_guard(self):
        result=self.run_recovery([{'state':'Error','message':LEASE_BUSY}]*3+[{'state':'Idle'}])
        self.assertEqual(result['state'],'Idle');self.assertEqual(len(self.pipes),4)
        self.assertEqual(len(self.guards),7);self.assertAlmostEqual(self.now,.6)
    def test_permanent_busy_deadline(self):
        with self.assertRaises(TimeoutError):self.run_recovery([{'state':'Error','message':LEASE_BUSY}])
        self.assertEqual(self.now,1);self.assertEqual(len(self.pipes),5)
    def test_other_errors_and_malformed_fail_promptly(self):
        for response in [{'state':'Error','message':'other'},{'state':'Blocked','message':LEASE_BUSY},{},None,[],{'state':'Error','message':LEASE_BUSY+' '}]:
            with self.subTest(response=response),self.assertRaises(AssertionError):self.run_recovery([response])
            self.assertEqual(len(self.pipes),1);self.assertEqual(self.now,0)
    def test_transport_exception_closes_without_retry(self):
        with self.assertRaises(OSError):self.run_recovery([OSError('synthetic')])
        self.assertEqual(len(self.pipes),1)
    def test_guard_failure_sends_no_recover(self):
        def fail():raise AssertionError('synthetic guard failure')
        with self.assertRaises(AssertionError):self.run_recovery([{'state':'Idle'}],guard=fail)
        self.assertEqual(self.pipes,[])
    def test_fixture_read_honors_shared_deadline(self):
        # Load only the class definition: fixture module import performs native
        # Windows calls and reads private runtime input. Neither belongs in tests.
        tree=ast.parse(pathlib.Path(__file__).with_name('windows_service_e2e.py').read_text())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Pipe')
        kernel=types.SimpleNamespace(PeekNamedPipe=lambda *a:self.fail('deadline ignored'))
        namespace={'time':types.SimpleNamespace(monotonic=lambda:10),'K':kernel}
        exec(compile(ast.Module(body=[cls],type_ignores=[]),'fixture-class','exec'),namespace)
        pipe=namespace['Pipe'].__new__(namespace['Pipe']);pipe.handle=1
        with self.assertRaises(TimeoutError):pipe.read(4,deadline=10)

if __name__=='__main__':unittest.main()
