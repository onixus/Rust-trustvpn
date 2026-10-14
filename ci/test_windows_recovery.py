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
    def test_idle_reply_at_deadline_is_success(self):
        # Reply completes exactly at the deadline: the guard was already released.
        self.now=0;self.pipes=[];test=self
        class Pipe:
            def __init__(self):test.pipes.append(self)
            def request(self,command,deadline):test.now=deadline;return {'state':'Idle'}
            def close(self):pass
        result=recover_after_crash(Pipe,lambda:None,timeout=1,interval=.2,clock=lambda:self.now,sleep=lambda d:None)
        self.assertEqual(result['state'],'Idle');self.assertEqual(len(self.pipes),1)
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
    def test_runners_copy_every_local_worker_import(self):
        # Workers run from an isolated copy; a missing sibling module fails only on the lab host.
        ci=pathlib.Path(__file__).parent
        def local_imports(name):
            found=set()
            for node in ast.walk(ast.parse((ci/name).read_text(encoding='utf-8'))):
                names=[a.name for a in node.names] if isinstance(node,ast.Import) else [node.module] if isinstance(node,ast.ImportFrom) and node.module else []
                found.update(n+'.py' for n in names if (ci/(n+'.py')).exists())
            return found
        def copied(runner):
            for node in ast.walk(ast.parse((ci/runner).read_text(encoding='utf-8'))):
                if isinstance(node,ast.For) and isinstance(node.iter,ast.List) and any(isinstance(e,ast.Constant) and e.value=='windows_service_e2e.py' for e in node.iter.elts):
                    return {e.value for e in node.iter.elts if isinstance(e,ast.Constant)}
            self.fail('Copy list not found in '+runner)
        authorized=copied('windows_authorized_full.py')
        for worker in ['windows_full_e2e.py','windows_selected_e2e.py','windows_production_e2e.py','windows_sleep_e2e.py','windows_service_e2e.py']:
            with self.subTest(worker=worker):self.assertLessEqual(local_imports(worker),authorized|{worker})
        full=copied('windows_full_runner.py')
        for worker in ['windows_full_e2e.py','windows_service_e2e.py']:
            with self.subTest(runner='windows_full_runner.py',worker=worker):self.assertLessEqual(local_imports(worker),full)

if __name__=='__main__':unittest.main()
