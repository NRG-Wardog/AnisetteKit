#!/usr/bin/env python3
"""Install or verify an explicit measurement-only overlay on ff5a1af's runtime.
No identity/Keychain/provider/staging/recovery behavior is edited. Release gates
are not called on modified inputs and are never rewritten to pretend acceptance.
"""
from __future__ import annotations
import argparse, hashlib, json, os, stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
BASE_HASHES={
 'loader': '6f8f156afe9ca4a49272f0f9b5d242a7cbdc56ad',
 'consumption': 'ade371dbbd687c251e4bade39c788442b7620c25',
}
def blob(data:bytes)->str:
 return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def once(text:str,old:str,new:str)->str:
 if text.count(old)!=1: raise ValueError('Changed injection anchor: '+old[:90])
 return text.replace(old,new,1)
def declaration(text:str,start:str)->str:
 at=text.index(start);brace=text.index('{',at);depth=0
 for end in range(brace,len(text)):
  if text[end]=='{':depth+=1
  if text[end]=='}':
   depth-=1
   if not depth:return text[at:end+1]
 raise ValueError('Unclosed declaration')
def native_changes(root:Path)->dict[Path,bytes]:
 loader=root/'Native/Loader/elf_loader_emulator.cpp';original=loader.read_bytes()
 if blob(original)!=BASE_HASHES['loader']:raise ValueError('Requires the exact ff5a1af loader')
 text=original.decode()
 helpers=(HERE/'observer_hooks.inc').read_text()
 text=once(text,'const AndroidSystemProperties kAndroidProperties;','const AndroidSystemProperties kAndroidProperties;\n\n'+helpers)
 text=once(text,'    g_pc_idx++;','    g_pc_idx++;\n    adi_observe_instruction(static_cast<EmulatorVM *>(user_data), address);')
 text=once(text,'    const std::string &name = it->second;','    const std::string &name = it->second;\n    ADIObservedImport observed(vm, address, name);')
 text=once(text,'    vm->loaded_libraries.push_back(lib);','    adi_observe_loaded(vm, buffer.data(), buffer.size(), lib);\n    vm->loaded_libraries.push_back(lib);')
 text=once(text,'        res = (int64_t)bytes_read;','        if (bytes_read > 0) adi_observe_guest_read(vm, guest_fd, buf_ptr, tmp.data(), size_t(bytes_read), observed_copy);\n        res = (int64_t)bytes_read;')
 text=once(text,'    uc_err err = uc_emu_start(vm->uc, proc_addr, kReturnAddress, timeout_us, max_count);',
 '''    if (activeADIConsumptionDebug) {
        activeADIConsumptionDebug->execution.active = true;
        activeADIConsumptionDebug->execution.modules = vm->diagnostic_modules;
        activeADIConsumptionDebug->execution.boundary();
    }
    uc_err err = uc_emu_start(vm->uc, proc_addr, kReturnAddress, timeout_us, max_count);''')
 text=once(text,'    if (err != UC_ERR_OK || pc != kReturnAddress) {',
 '''    if (activeADIConsumptionDebug && activeADIConsumptionDebug->phase == ADIConsumptionDebug::Constructors &&
        (err != UC_ERR_OK || pc != kReturnAddress))
        adi_execution::Capture::increment(activeADIConsumptionDebug->execution.constructorFailures);
    if (err != UC_ERR_OK || pc != kReturnAddress) {''')
 header=root/'Native/Loader/elf_loader_emulator.h';hs=header.read_text()
 hs=once(hs,'#include "anisette_base.h"','#include "anisette_base.h"\n#include "adi_execution_debug.h"')
 hs=once(hs,'    bool read_only_filesystem = false;','    adi_execution::Modules diagnostic_modules;\n    bool read_only_filesystem = false;')
 consumption=root/'Native/Loader/adi_consumption_debug.h';cs=consumption.read_text()
 if blob(cs.encode())!=BASE_HASHES['consumption']:raise ValueError('Unexpected consumption producer')
 cs=once(cs,'#include <cerrno>','#include <cerrno>\n#include "adi_execution_debug.h"')
 cs=once(cs,'struct ADIConsumptionDebug {','struct ADIConsumptionDebug {\n    adi_execution::Capture execution;')
 cs=once(cs,'        size_t used = static_cast<size_t>(snprintf(encoded,sizeof(encoded),"v2|%u|%u|%u",truncated ? 1u : 0u,comparison,coverage()));\n        for (unsigned i=0;i<count;++i) {',
 '''        char executionText[1321] = {};
        const bool detail = execution.active && execution.encode(executionText,sizeof(executionText));
        const unsigned begin = detail && count > 8 ? count - 8 : 0;
        const bool loss = truncated || begin != 0 || (execution.active && !detail);
        size_t used = static_cast<size_t>(snprintf(encoded,sizeof(encoded),"%s|%u|%u|%u",detail ? "v3" : "v2",loss ? 1u : 0u,comparison,loss ? 0u : coverage()));
        if (detail) used += static_cast<size_t>(snprintf(encoded+used,sizeof(encoded)-used,"|%s",executionText));
        for (unsigned i=begin;i<count;++i) {''')
 swift=root/'Sources/AnisetteDataProvider.swift';ss=swift.read_text();old=declaration(ss,'private enum TemporaryADIConsumptionTrace')
 new=old.replace('rows.count <= 36','rows.count <= 37').replace('rows[0] == "v2"','rows[0] == "v2" || rows[0] == "v3"')
 new=once(new,'            headerCount = 4', '''            if rows[0] == "v3" {
                guard rows.count >= 5, ADIExecutionWire.valid(String(rows[4])) else { return "" }
                headerCount = 5
            } else { headerCount = 4 }''')
 ss=once(ss,old,new)+'\n'+(HERE/'ExecutionWire.swift').read_text()
 return {loader:text.encode(),header:hs.encode(),consumption:cs.encode(),swift:ss.encode(),root/'Native/Loader/adi_execution_debug.h':(HERE/'adi_execution_debug.h').read_bytes()}
def wire_change(path:Path)->bytes:
 text=path.read_text();old=declaration(text,'public struct V3TemporaryADIConsumption')
 new=once(old,'    private let rows: [[Int]]','    private let rows: [[Int]]\n    private let execution: String?')
 new=once(new,'        let offset: Int','        let offset: Int\n        var execution: String? = nil')
 new=new.replace('pieces[0] == "v2"','pieces[0] == "v2" || pieces[0] == "v3"')
 new=once(new,'            offset = 4', '''            if pieces[0] == "v3" {
                guard pieces.count >= 5, ADIExecutionWire.valid(String(pieces[4])) else { return nil }
                execution = String(pieces[4]); offset = 5
            } else { offset = 4 }''')
 new=once(new,'        rows = decoded','        rows = decoded\n        self.execution = execution')
 new=once(new,'private init(truncated: Bool, comparison: Int?, inputCovered: Bool, rows: [[Int]])','private init(truncated: Bool, comparison: Int?, inputCovered: Bool, rows: [[Int]], execution: String? = nil)')
 new=once(new,'        self.rows = rows','        self.rows = rows\n        self.execution = execution')
 new=once(new,'let prefix = comparison.map { "v2|\\(truncated ? 1 : 0)|\\($0)|\\(inputCovered ? 1 : 0)" }',
 'let version = execution == nil ? "v2" : "v3"\n        let prefix = comparison.map { "\\(version)|\\(truncated ? 1 : 0)|\\($0)|\\(inputCovered ? 1 : 0)" + (execution.map { "|" + $0 } ?? "") }')
 new=once(new,'        return "\\nDEBUG TEMPORARY adi_consumption=\\(encoded)"',
 '''        let consumption = Self(truncated: truncated, comparison: comparison, inputCovered: inputCovered, rows: rows).encoded
        return "\\nDEBUG TEMPORARY adi_consumption=\\(consumption)" + (execution.map { "\\nDEBUG TEMPORARY adi_execution=" + $0 } ?? "")''')
 new=once(new,'            if trace.rows.isEmpty {', '''            if trace.rows.isEmpty, let detail = trace.execution, let trimmed = ADIExecutionWire.trim(detail) {
                trace = Self(truncated: true, comparison: trace.comparison, inputCovered: false, rows: [], execution: trimmed)
                continue
            }
            if trace.rows.isEmpty {''')
 new=once(new,'trace = Self(truncated: true, comparison: trace.comparison, inputCovered: trace.inputCovered, rows: Array(trace.rows.dropFirst()))',
 'trace = Self(truncated: true, comparison: trace.comparison, inputCovered: false, rows: Array(trace.rows.dropFirst()), execution: trace.execution)')
 return (once(text,old,new)+'\n'+(HERE/'ExecutionWire.swift').read_text()).encode()
def install_file(path:Path,data:bytes)->None:
 path.parent.mkdir(parents=True,exist_ok=True)
 mode=stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
 if path.exists():path.chmod(mode|stat.S_IWUSR)
 try:path.write_bytes(data)
 finally:path.chmod(mode)
def main()->None:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--anisette',type=Path,required=True);p.add_argument('--host',type=Path,required=True);p.add_argument('--side',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);p.add_argument('--verify',action='store_true');a=p.parse_args()
 roots={'AnisetteKit':a.anisette.resolve(),'LiveContainer':a.host.resolve(),'SideStore':a.side.resolve()}
 if a.verify:
  record=json.loads(a.receipt.read_text())
  for item in record['files']:
   path=roots[item['owner']]/item['path']
   if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=item['after_sha256']:raise ValueError('Changed compiler input '+item['path'])
  print('Exact diagnostic inputs unchanged: PASS');return
 changes=native_changes(roots['AnisetteKit'])
 for path in [roots['LiveContainer']/'SideStoreSupport/SideStore.swift',roots['SideStore']/'AltStore/AppDelegate.swift']:changes[path]=wire_change(path)
 items=[]
 for path,data in changes.items():
  if path.is_symlink():raise ValueError('Linked input')
  owner=next(k for k,v in roots.items() if path.is_relative_to(v))
  items.append({'owner':owner,'path':str(path.relative_to(roots[owner])), 'before_sha256':hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None,'after_sha256':hashlib.sha256(data).hexdigest()})
 for path,data in changes.items():install_file(path,data)
 record={'schema':1,'baseline_candidate':'ff5a1af34fe1fef443c1f82e614c073e21054970','purpose':'measurement_only_ADI_rejection','device_login_verified':False,'runtime_behavior_fixes':False,'files':items}
 a.receipt.parent.mkdir(parents=True,exist_ok=True);a.receipt.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
 print('Measurement overlay installed with exact input receipt')
if __name__=='__main__':main()
