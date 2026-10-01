"""Exercise a real single-file document grant with synthetic data in the installed Flatpak."""
import dbus,os,pathlib,tempfile,subprocess
bus=dbus.SessionBus();portal=dbus.Interface(bus.get_object('org.freedesktop.portal.Documents','/org/freedesktop/portal/documents'),'org.freedesktop.portal.Documents')
with tempfile.TemporaryDirectory(prefix='rtrust-document-probe-') as directory:
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    try:document=str(portal.AddNamed(dbus.types.UnixFd(fd),dbus.ByteArray(b'probe.txt\0'),True,False))
    finally:os.close(fd)
    try:
        portal.GrantPermissions(document,'org.rtrusttunnel.Native',['read','write','delete'])
        path='/run/user/1000/doc/'+document+'/probe.txt'
        code='set -eu; temp=$(mktemp "${1%/*}/.rtrust-probe-XXXXXX"); chmod 600 "$temp"; printf "%s" RTRUST_SYNTHETIC_EXPORT > "$temp"; mv "$temp" "$1"; cat "$1"'
        result=subprocess.run(['flatpak','run','--user','--command=sh','org.rtrusttunnel.Native','-c',code,'sh',path],capture_output=True,text=True,timeout=20)
        print('Atomic document export return code:',result.returncode)
        print(result.stdout);print(result.stderr)
        assert result.returncode==0, 'Atomic document export failed'
        if result.returncode==0:
            assert pathlib.Path(directory,'probe.txt').read_text()=='RTRUST_SYNTHETIC_EXPORT'
            assert pathlib.Path(directory,'probe.txt').stat().st_mode&0o077==0
            print('PASS real document portal single-file grant supports private atomic export and readback')
    finally:portal.Delete(document)
