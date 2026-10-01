"""Real StatusNotifierItem/DBusMenu exchange under a disposable session bus.
The watcher is a test host; the app uses its real ksni backend and Wayland window.
"""
import argparse, os, subprocess, time
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
parser = argparse.ArgumentParser()
parser.add_argument('--flatpak-installation')
args = parser.parse_args()
bus = dbus.SessionBus()
name = dbus.service.BusName('org.kde.StatusNotifierWatcher', bus)
registered = []
activated = False
registered_at = None
class Watcher(dbus.service.Object):
    @dbus.service.method('org.kde.StatusNotifierWatcher', in_signature='s', out_signature='', sender_keyword='sender')
    def RegisterStatusNotifierItem(self, service, sender=None):
        global registered_at
        registered.append((str(sender),str(service)) if str(service).startswith('/') else (str(service),'/StatusNotifierItem'))
        registered_at = time.monotonic()
    @dbus.service.method('org.freedesktop.DBus.Properties', in_signature='ss', out_signature='v')
    def Get(self, interface, prop):
        return self.GetAll(interface)[prop]
    @dbus.service.method('org.freedesktop.DBus.Properties', in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        return {'IsStatusNotifierHostRegistered':dbus.Boolean(True), 'RegisteredStatusNotifierItems':dbus.Array([name+path for name,path in registered], signature='s'), 'ProtocolVersion':dbus.Int32(0)}
watcher = Watcher(bus, '/StatusNotifierWatcher')
env = dict(os.environ, RTRUST_CI_EXPECT_TRAY='1')
command = (['flatpak','run','--installation='+args.flatpak_installation,
            '--env=RTRUST_CI_EXPECT_TRAY=1','org.rtrusttunnel.Native']
           if args.flatpak_installation else ['target/release/rtrust-native'])
process = subprocess.Popen(command+['--ci-tray-smoke'], env=env)
loop = GLib.MainLoop()
deadline = time.monotonic()+20
inspected = False
errors = []
def tick():
    global inspected, activated
    if registered and not inspected:
        try:
            name,path=registered[0]
            obj=bus.get_object(name,path)
            props=dbus.Interface(obj,'org.freedesktop.DBus.Properties')
            assert str(props.Get('org.kde.StatusNotifierItem','Id'))=='org.rtrusttunnel.Native'
            menu=props.Get('org.kde.StatusNotifierItem','Menu')
            layout=dbus.Interface(bus.get_object(name,str(menu)),'com.canonical.dbusmenu').GetLayout(0,-1,[])
            assert 'Открыть' in str(layout) and 'Выход' in str(layout)
            inspected=True
        except Exception as error:
            errors.append(str(error)); process.terminate()
    if inspected and not activated and time.monotonic()-registered_at > .65:
        try:
            dbus.Interface(bus.get_object(*registered[0]),'org.kde.StatusNotifierItem').Activate(0,0)
            activated=True
        except Exception as error:
            errors.append(str(error));process.terminate()
    if process.poll() is not None or time.monotonic()>deadline:
        loop.quit(); return False
    return True
GLib.timeout_add(40,tick)
try:
    loop.run()
    assert process.wait(timeout=5)==0, errors
    assert inspected and activated, 'StatusNotifierItem menu/activation was not exercised'
    assert not errors, errors
    print('PASS Wayland tray: real DBus registration/menu, hide and restore')
finally:
    if process.poll() is None:process.kill();process.wait()
