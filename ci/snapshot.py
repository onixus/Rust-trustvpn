"""Freeze the local project into a Jenkins workspace."""
import hashlib,json,pathlib,shutil,subprocess,sys
source=pathlib.Path(__file__).resolve().parents[1];dest=pathlib.Path(sys.argv[1]).resolve()
if source==dest:raise SystemExit('Snapshot requires a separate directory')
dest.mkdir(parents=True,exist_ok=True)
# Release snapshots must not pick up unrelated, untracked work or local secrets.
tracked=set(subprocess.check_output(['git','-C',str(source),'ls-files','-z']).decode().split('\0'))
def ignore(directory,names):
    base=pathlib.Path(directory).relative_to(source)
    return [name for name in names if not any(path == str(base/name) or path.startswith(str(base/name)+'/') for path in tracked)]
for name in ['.gitleaks.toml','.gitignore','Cargo.toml','Cargo.lock','Readme.md','readme_ru.md','LICENSE','Jenkinsfile','Jenkinsfile.linux','Jenkinsfile.android','apps','crates','scripts','ci','server','vendor','examples','docs','deploy','packaging','.github']:
    path=source/name
    if not path.exists():continue
    if path.is_dir():shutil.copytree(path,dest/name,dirs_exist_ok=True,ignore=ignore)
    else:shutil.copy2(path,dest/name)
files={str(p.relative_to(dest)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(dest.rglob('*')) if p.is_file()}
(dest/'source-manifest.json').write_text(json.dumps(files,indent=2)+'\n')
print('Snapshot SHA256: '+hashlib.sha256((dest/'source-manifest.json').read_bytes()).hexdigest())
