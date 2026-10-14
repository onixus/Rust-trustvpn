"""Portable bounded recovery handshake; no Windows imports or system effects."""
import time

LEASE_BUSY='Служба уже обслуживает подключение'

def recover_after_crash(pipe_factory,assert_guard,timeout=20,interval=.2,*,clock=time.monotonic,sleep=time.sleep):
    if timeout<=0 or interval<=0:raise ValueError('Invalid recovery timing')
    deadline=clock()+timeout
    while clock()<deadline:
        assert_guard()
        if clock()>=deadline:break
        pipe=pipe_factory()
        try:
            if clock()>=deadline:raise TimeoutError('Recovery deadline expired')
            response=pipe.request(dict(op='Recover'),deadline=deadline)
        finally:pipe.close()
        if not isinstance(response,dict):raise AssertionError('Malformed recovery response')
        # A completed Recover has already released the guard; never report it as a timeout.
        if response.get('state')=='Idle':return response
        if clock()>=deadline:raise TimeoutError('Recovery deadline expired')
        if response.get('state')!='Error' or response.get('message')!=LEASE_BUSY:
            raise AssertionError('Unexpected recovery response')
        assert_guard()
        remaining=deadline-clock()
        if remaining<=0:break
        sleep(min(interval,remaining))
    raise TimeoutError('Recovery lease did not become available')
