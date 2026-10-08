#!/usr/bin/env python3
"""Test actual generated Swift decoders and pure native observer storage.
This test does not use Apple ADI libraries or a device identity.
"""
import argparse, hashlib, json, shutil, subprocess, tempfile
from pathlib import Path
from prepare_trace import declaration
HERE=Path(__file__).resolve().parent
NATIVE=r'''
#include "adi_execution_debug.h"
#include <iostream>
#include <vector>
#include <cassert>
int main(){
 for(size_t n: {size_t(0),size_t(3),size_t(55),size_t(56),size_t(63),size_t(64),size_t(65),size_t(1000)}){
  std::vector<uint8_t>b(n);for(size_t i=0;i<n;i++)b[i]=uint8_t(i*19+3);char h[65];adi_execution::sha256(b.data(),b.size(),h);std::cout<<n<<" "<<h<<"\n";}
 adi_execution::Capture c;c.modules.add(1,0x1000,0x1100,0x1200);
 assert(c.modules.locate(0x1000).module==0);assert(c.modules.locate(0x1100).offset==0x100);
 assert(c.modules.locate(0x1200).module==0);
 c.observe({1,0x100},false,true);c.observe({1,0x104},true,true);
 assert(c.transitions==1&&c.first.before.offset==0x100&&c.first.after.offset==0x104);
 c.observe({1,0x108},true,true);assert(c.transitions==1);
 c.boundary();c.observe({1,0x110},true,true);assert(c.transitions==2&&c.last.before.module==0);
 c.guestResult(1);c.guestResult(2);c.guestResult(1);assert(c.guest==2);
 for(unsigned i=0;i<100;++i)c.imports.push({5,39,i,{1,0x100},3,0});
 assert(c.imports.count==8&&c.imports.omitted==92);
 c.returns.push({1,0x110});errno=123;char out[1321];assert(c.encode(out,sizeof(out)));assert(errno==123);
 std::cout<<"TRACE="<<out<<"\n";
 char small[4];assert(!c.encode(small,sizeof(small)));
 std::cout<<"NATIVE_STORAGE_PASS\n";
}
'''
SWIFT=r'''
let detail = "x1;H,0,0;S,0,3,1,0,0,1,15;F,1,256,1,260;L,1,256,1,260;P,1,256;R,1,264;I,5,39,1,1,100,3,0"
let encoded = "v3|0|1|1|" + detail + "|5,1,1,1,0,639,639,0"
precondition(ADIExecutionWire.valid(detail))
precondition(!ADIExecutionWire.valid(detail + ";SECRET,user"))
precondition(!ADIExecutionWire.valid(detail.replacingOccurrences(of: "H,0,0", with: "H,sensitive,0")))
precondition(!ADIExecutionWire.valid(detail.replacingOccurrences(of: "P,1,256", with: "P,0,256")))
precondition(!ADIExecutionWire.valid(detail.replacingOccurrences(of: "S,0,", with: "S,32,")))
precondition(!ADIExecutionWire.valid(detail.replacingOccurrences(of: "I,5,39", with: "I,5,45")))
precondition(!ADIExecutionWire.valid(detail.replacingOccurrences(of: "S,0,3", with: "S,00,3")))
let native = TemporaryADIConsumptionTrace.suffix(encoded)
precondition(!native.isEmpty)
precondition(TemporaryADIConsumptionTrace.suffix(encoded + "|0").isEmpty)
let result = V3TemporaryADIConsumption.splitDescription("ADIOTPRequest failed: -45061" + native)
precondition(result.base == "ADIOTPRequest failed: -45061")
precondition(result.trace?.encoded == encoded)
precondition(result.trace!.technicalDetails.contains("adi_execution=" + detail))
precondition(result.trace!.technicalDetails.contains("adi_consumption=v2|0|1|1|5,1,1,1,0,639,639,0"))
for old in ["v1|0|5,1,1,1,0,639,639,0", "v2|0|1|1|5,1,1,1,0,639,639,0"] {
 precondition(V3TemporaryADIConsumption(encoded: old)?.encoded == old)
 precondition(!TemporaryADIConsumptionTrace.suffix(old).isEmpty)
}
let context = V3TemporaryADIConsumption.sanitizingContext([V3TemporaryADIConsumption.contextKey: encoded, "native_code":"-45061"])
precondition(context[V3TemporaryADIConsumption.contextKey] == encoded)
var payload: [String:Any] = ["signingContext":context,"error_code":-45061,"padding":String(repeating:"q",count:3500)]
payload = V3TemporaryADIConsumption.boundingWire(payload)
precondition(payload["error_code"] as? Int == -45061)
if let c = payload["signingContext"] as? [String:String], let v = c[V3TemporaryADIConsumption.contextKey] {
 precondition(V3TemporaryADIConsumption(encoded:v) != nil)
 precondition(try! PropertyListSerialization.data(fromPropertyList:payload,format:.binary,options:0).count <= 4096)
}
var t = detail; var steps=0
while let s = ADIExecutionWire.trim(t) {precondition(s != t);precondition(ADIExecutionWire.valid(s));t=s;steps+=1;precondition(steps<30)}
precondition(steps == 3)
print("SWIFT_WIRE_PASS")
'''
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=60)
 if r.returncode: raise RuntimeError(r.stdout+r.stderr)
 return r.stdout

def main():
 p=argparse.ArgumentParser();p.add_argument('--anisette',type=Path,required=True);p.add_argument('--host',type=Path,required=True);p.add_argument('--side',type=Path,required=True);a=p.parse_args()
 with tempfile.TemporaryDirectory() as tmp:
  tmp=Path(tmp);(tmp/'test.cpp').write_text(NATIVE)
  run([shutil.which('clang++') or 'c++','-std=c++17','-fsanitize=address,undefined','-I',str(HERE),str(tmp/'test.cpp'),'-o',str(tmp/'native')])
  out=run([str(tmp/'native')]);print(out)
  for line in out.splitlines():
   if line[:1].isdigit():
    n,h=line.split();expected=hashlib.sha256(bytes((i*19+3)%256 for i in range(int(n)))).hexdigest();assert expected==h
  provider=declaration((a.anisette/'Sources/AnisetteDataProvider.swift').read_text(),'private enum TemporaryADIConsumptionTrace')
  consumers=[declaration(path.read_text(),'public struct V3TemporaryADIConsumption') for path in [a.host/'SideStoreSupport/SideStore.swift',a.side/'AltStore/AppDelegate.swift']]
  assert consumers[0]==consumers[1], 'Host/service wire definitions differ'
  source='import Foundation\npublic enum V3TemporaryAnisetteTrace {public static let temporaryAnisetteTraceEnabled = true}\n'+consumers[0]+'\n'+provider+'\n'+(HERE/'ExecutionWire.swift').read_text()+SWIFT
  (tmp/'main.swift').write_text(source)
  run(['swiftc',str(tmp/'main.swift'),'-o',str(tmp/'swift-test')]);print(run([str(tmp/'swift-test')]))
 print('Pure native observer and actual Swift wire contracts: PASS')
if __name__=='__main__': main()
