import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const cli=new URL('../bin/cookie-consent-config-checker.mjs',import.meta.url).pathname;
const policy={schemaVersion:'1',complete:true,categories:[{id:'essential',required:true,defaultGranted:true},{id:'analytics',required:false,defaultGranted:false}],scripts:[{id:'analytics-loader',category:'analytics'}]};
const capture={schemaVersion:'1',complete:true,categories:policy.categories,scripts:policy.scripts,events:[{type:'grant',category:'analytics'},{type:'load',script:'analytics-loader'}]};
function fixture(run){const root=mkdtempSync(join(tmpdir(),'consent-check-'));try{writeFileSync(join(root,'policy.json'),JSON.stringify(policy));writeFileSync(join(root,'capture.json'),JSON.stringify(capture));return run(root);}finally{rmSync(root,{recursive:true,force:true});}}
const invoke=root=>spawnSync(process.execPath,[cli,'--root',root,'--policy','policy.json','--capture','capture.json'],{encoding:'utf8'});

test('CLI emits identical JSON for identical complete local evidence',()=>fixture(root=>{
  const a=invoke(root),b=invoke(root);assert.equal(a.status,0);assert.equal(a.stdout,b.stdout);assert.equal(JSON.parse(a.stdout).status,'pass');
}));
test('bad usage is empty stdout while unreadable evidence has incomplete JSON',()=>fixture(root=>{
  const bad=spawnSync(process.execPath,[cli,'--oops'],{encoding:'utf8'});assert.equal(bad.status,2);assert.equal(bad.stdout,'');
  const unreadable=spawnSync(process.execPath,[cli,'--root',root,'--policy','missing.json','--capture','capture.json'],{encoding:'utf8'});assert.equal(unreadable.status,2);assert.equal(JSON.parse(unreadable.stdout).findings[0].ruleId,'input-unreadable');
}));
test('policy byte bound accepts 262144 and refuses 262145',()=>fixture(root=>{
  const base=JSON.stringify(policy),name=join(root,'policy.json');writeFileSync(name,base+' '.repeat(262144-Buffer.byteLength(base)));assert.equal(invoke(root).status,0);
  writeFileSync(name,base+' '.repeat(262145-Buffer.byteLength(base)));const r=invoke(root);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).findings[0].ruleId,'byte-limit');
}));
test('capture byte bound accepts 1048576 and refuses 1048577',()=>fixture(root=>{
  const base=JSON.stringify(capture),name=join(root,'capture.json');writeFileSync(name,base+' '.repeat(1048576-Buffer.byteLength(base)));assert.equal(invoke(root).status,0);
  writeFileSync(name,base+' '.repeat(1048577-Buffer.byteLength(base)));const r=invoke(root);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).findings[0].ruleId,'byte-limit');
}));
test('escaping capture symlink is refused without reading its content',()=>{
  const root=mkdtempSync(join(tmpdir(),'consent-root-')),outside=mkdtempSync(join(tmpdir(),'consent-out-'));
  try{writeFileSync(join(root,'policy.json'),JSON.stringify(policy));writeFileSync(join(outside,'secret.json'),'PRIVATE_SENTINEL');symlinkSync(join(outside,'secret.json'),join(root,'capture.json'));const r=invoke(root);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).findings[0].ruleId,'input-unreadable');assert.doesNotMatch(r.stdout,/PRIVATE_SENTINEL/);}
  finally{rmSync(root,{recursive:true,force:true});rmSync(outside,{recursive:true,force:true});}
});
test('malformed UTF-8 and malformed JSON are incomplete without echoing input',()=>fixture(root=>{
  const head=JSON.stringify(capture).slice(0,-1)+',"extra":"';
  writeFileSync(join(root,'capture.json'),Buffer.concat([Buffer.from(head),Buffer.from([0xff]),Buffer.from('"}')]));
  const badUtf=invoke(root);assert.equal(badUtf.status,2);assert.equal(JSON.parse(badUtf.stdout).findings[0].ruleId,'input-unreadable');
  writeFileSync(join(root,'capture.json'),'PRIVATE_SENTINEL');
  const badJson=invoke(root);assert.equal(badJson.status,2);assert.equal(JSON.parse(badJson.stdout).findings[0].ruleId,'input-unreadable');assert.doesNotMatch(badJson.stdout+badJson.stderr,/PRIVATE_SENTINEL/);
}));
test('duplicate decoded JSON keys reject ambiguous config and capture evidence',()=>fixture(root=>{
  const duplicate=JSON.stringify(capture).replace('"complete":true','"complete":false,"comple\\u0074e":true');
  writeFileSync(join(root,'capture.json'),duplicate);
  const unknown=invoke(root);assert.equal(unknown.status,2);assert.equal(JSON.parse(unknown.stdout).status,'incomplete');
  writeFileSync(join(root,'capture.json'),JSON.stringify(capture));
  const config=JSON.stringify(policy).replace('"complete":true','"complete":false,"comple\\u0074e":true');
  writeFileSync(join(root,'policy.json'),config);
  const invalid=invoke(root);assert.equal(invalid.status,2);assert.equal(invalid.stdout,'');
}));
