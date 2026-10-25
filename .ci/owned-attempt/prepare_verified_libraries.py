#!/usr/bin/env python3
"""Prepare exact recognized built-in libraries without executing them."""
import argparse, hashlib, json, pathlib, zipfile
def require(condition,message):
 if not condition:raise RuntimeError(message)
EXPECTED={
 'libCoreADI.so':(1792592,'9d5b557cf3faf88c34c394ab2cd7fc1a3b4acf3aed51f28cd0bc093858107c22'),
 'libstoreservicescore.so':(2388480,'bd335e6963ba5ae2f5babca613435ad56d2660a9aee37df35f876c458d105ce4')}
p=argparse.ArgumentParser();p.add_argument('--archive',required=True,type=pathlib.Path);p.add_argument('--output',required=True,type=pathlib.Path);a=p.parse_args()
require(a.archive.stat().st_size==142139820,'Recognized archive size mismatch')
require(not a.output.exists(),'Output must be exclusively new')
verified={}
with zipfile.ZipFile(a.archive) as z:
 for name,(size,digest) in EXPECTED.items():
  entry='lib/arm64-v8a/'+name
  require(z.namelist().count(entry)==1,'Duplicate library entry')
  info=z.getinfo(entry);require(info.file_size==size,'Library size mismatch')
  data=z.read(info);require(len(data)==size and hashlib.sha256(data).hexdigest()==digest,'Library digest mismatch')
  verified[name]=data
a.output.mkdir(mode=0o700)
for name,data in verified.items():
 with (a.output/name).open('xb') as f:f.write(data)
 (a.output/name).chmod(0o400)
print(json.dumps({'archive_sha256_observed':hashlib.sha256(a.archive.read_bytes()).hexdigest(),'recognized_libraries':{name:{'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in verified.items()}},sort_keys=True))
