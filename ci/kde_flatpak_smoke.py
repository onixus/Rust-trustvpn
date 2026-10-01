"""Exercise only our smoke windows/items in an existing Plasma Wayland session."""
import os
import subprocess
import time
import dbus

assert os.environ.get('XDG_SESSION_TYPE') == 'wayland'
assert 'KDE' in os.environ.get('XDG_CURRENT_DESKTOP', '')
APP = 'org.rtrusttunnel.Native'
env = dict(os.environ); env.pop('DISPLAY', None)
for mode in ('--ci-smoke','--ci-settings-smoke','--ci-portal-smoke'):
    result = subprocess.run(['flatpak','run','--user','--env=WAYLAND_DEBUG=1',APP,mode],
                            env=env,text=True,capture_output=True,timeout=40)
    assert result.returncode == 0, result.stderr[-3000:]
    assert 'set_app_id("org.rtrusttunnel.Native")' in result.stderr
    print('PASS physical Plasma Wayland '+mode,flush=True)
bus = dbus.SessionBus()
watcher = dbus.Interface(bus.get_object('org.kde.StatusNotifierWatcher','/StatusNotifierWatcher'),
                         'org.freedesktop.DBus.Properties')
def items():
    return set(map(str,watcher.Get('org.kde.StatusNotifierWatcher','RegisteredStatusNotifierItems')))
before = items()
process = subprocess.Popen(['flatpak','run','--user','--env=RTRUST_CI_EXPECT_TRAY=1',APP,'--ci-tray-smoke'],
                           env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    deadline=time.monotonic()+12
    inspected=False
    while time.monotonic()<deadline and process.poll() is None:
        for item in items()-before:
            name,sep,path=item.partition('/')
            obj=bus.get_object(name,'/'+path if sep else '/StatusNotifierItem')
            props=dbus.Interface(obj,'org.freedesktop.DBus.Properties')
            if str(props.Get('org.kde.StatusNotifierItem','Id'))!=APP:continue
            menu=str(props.Get('org.kde.StatusNotifierItem','Menu'))
            layout=dbus.Interface(bus.get_object(name,menu),'com.canonical.dbusmenu').GetLayout(0,-1,[])
            assert 'Открыть' in str(layout) and 'Выход' in str(layout)
            time.sleep(.8)
            dbus.Interface(obj,'org.kde.StatusNotifierItem').Activate(0,0)
            inspected=True;break
        if inspected:break
        time.sleep(.1)
    assert inspected,'Flatpak did not register with the real Plasma tray'
    assert process.wait(timeout=10)==0,'Tray hide/restore failed'
    print('PASS physical Plasma tray registration/menu/hide/restore',flush=True)
finally:
    if process.poll() is None:process.terminate();process.wait(timeout=5)
result=subprocess.run(['flatpak','run','--user',APP,'--ci-service-smoke'],env=env,text=True,capture_output=True,timeout=15)
assert result.returncode==0,result.stderr
print(result.stdout.strip(),flush=True)
