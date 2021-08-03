import test from 'node:test';
import assert from 'node:assert/strict';
import {evaluateConsent, LIMITS, TOOL_ID} from '../src/index.mjs';

const policy = () => ({schemaVersion:'1',complete:true,categories:[{id:'essential',required:true,defaultGranted:true},{id:'analytics',required:false,defaultGranted:false}],scripts:[{id:'analytics-loader',category:'analytics'}]});
const capture = () => ({schemaVersion:'1',complete:true,categories:policy().categories,scripts:policy().scripts,events:[{type:'grant',category:'analytics'},{type:'load',script:'analytics-loader'}]});

test('a complete consented load passes without a legal-compliance claim',()=>{
  const r=evaluateConsent(policy(),capture(),{now:()=>0});
  assert.equal(TOOL_ID,'cookie-consent-config-checker');
  assert.equal(r.status,'pass'); assert.ok(r.summary.checked>0); assert.deepEqual(r.findings,[]);
  assert.equal(JSON.stringify(r).includes('analytics-loader'),false);
});
test('an optional script loading before consent fails at its event ordinal',()=>{
  const c=capture(); c.events.reverse();
  const r=evaluateConsent(policy(),c,{now:()=>0});
  assert.equal(r.status,'fail');
  assert.deepEqual(r.findings.map(f=>[f.ruleId,f.location.file,f.location.pointer]),[['script-before-consent','@capture','/events/0']]);
});
test('a complete export with changed defaults or mappings fails comparison',()=>{
  const c=capture(); c.categories[1]={...c.categories[1],defaultGranted:true};
  assert.equal(evaluateConsent(policy(),c,{now:()=>0}).findings[0].ruleId,'category-mismatch');
  const d=capture(); d.scripts[0]={...d.scripts[0],category:'essential'};
  assert.equal(evaluateConsent(policy(),d,{now:()=>0}).findings[0].ruleId,'mapping-mismatch');
});
test('unknown load and missing completeness evidence cannot pass',()=>{
  const c=capture(); c.events[1].script='private-unknown';
  assert.equal(evaluateConsent(policy(),c,{now:()=>0}).status,'incomplete');
  for(const side of ['policy','capture']){const p=policy(),d=capture();delete (side==='policy'?p:d).complete;assert.equal(evaluateConsent(p,d,{now:()=>0}).status,'incomplete');}
});
test('a policy mapping to an absent category reports the policy source',()=>{
  const p=policy();p.scripts[0].category='absent';
  const r=evaluateConsent(p,capture(),{now:()=>0});assert.equal(r.status,'incomplete');assert.equal(r.findings[0].location.file,'@policy');
});
test('optional default grant is a technical policy failure',()=>{
  const p=policy(),c=capture();p.categories[1].defaultGranted=true;c.categories[1].defaultGranted=true;
  assert.equal(evaluateConsent(p,c,{now:()=>0}).findings[0].ruleId,'optional-default-granted');
});
test('a required category cannot be configured as denied by default',()=>{
  const p=policy(),c=capture();p.categories[0].defaultGranted=false;c.categories[0]={...c.categories[0],defaultGranted:false};
  const r=evaluateConsent(p,c,{now:()=>0});assert.equal(r.status,'fail');assert.equal(r.findings[0].ruleId,'required-default-denied');
});
test('record and depth boundaries accept N and reject N+1',()=>{
  const p=policy(),c=capture();
  p.categories=Array.from({length:LIMITS.categories},(_,i)=>({id:`c${i}`,required:false,defaultGranted:false})); c.categories=structuredClone(p.categories);p.scripts=[{id:'analytics-loader',category:'c0'}];c.scripts=structuredClone(p.scripts);c.events=[{type:'grant',category:'c0'},{type:'load',script:'analytics-loader'}];
  assert.equal(evaluateConsent(p,c,{now:()=>0}).status,'pass');
  p.categories.push({id:'extra',required:false,defaultGranted:false});assert.equal(evaluateConsent(p,c,{now:()=>0}).findings[0].ruleId,'record-limit');
  const a=policy(),b=capture();let x=a;for(let i=0;i<LIMITS.depth;i++){x.extra={};x=x.extra;}
  assert.equal(evaluateConsent(a,b,{now:()=>0}).status,'pass');x.extra={};assert.equal(evaluateConsent(a,b,{now:()=>0}).findings[0].ruleId,'depth-limit');
});
test('script and event counts each accept N and reject N+1',()=>{
  const p=policy(),c=capture();p.scripts=Array.from({length:LIMITS.scripts},(_,i)=>({id:`script-${i}`,category:'analytics'}));c.scripts=structuredClone(p.scripts);c.events=[];
  assert.equal(evaluateConsent(p,c,{now:()=>0}).status,'pass');
  p.scripts.push({id:'extra-script',category:'analytics'});assert.equal(evaluateConsent(p,c,{now:()=>0}).findings[0].ruleId,'record-limit');
  const d=capture();d.events=Array.from({length:LIMITS.events},()=>({type:'grant',category:'analytics'}));
  assert.equal(evaluateConsent(policy(),d,{now:()=>0}).status,'pass');
  d.events.push({type:'grant',category:'analytics'});assert.equal(evaluateConsent(policy(),d,{now:()=>0}).findings[0].ruleId,'record-limit');
});
test('capture depth 16 passes and 17 is incomplete',()=>{
  const c=capture();let x=c;for(let i=0;i<LIMITS.depth;i++){x.extra={};x=x.extra;}
  assert.equal(evaluateConsent(policy(),c,{now:()=>0}).status,'pass');x.extra={};assert.equal(evaluateConsent(policy(),c,{now:()=>0}).findings[0].ruleId,'depth-limit');
});
test('revoke before a later load fails and event findings are code-unit sorted',()=>{
  const c=capture();c.events=[{type:'grant',category:'analytics'},...Array.from({length:10},()=>({type:'revoke',category:'analytics'}))];c.events[2]={type:'load',script:'analytics-loader'};c.events[10]={type:'load',script:'analytics-loader'};
  const r=evaluateConsent(policy(),c,{now:()=>0});assert.equal(r.status,'fail');assert.deepEqual(r.findings.map(f=>f.location.pointer),['/events/10','/events/2']);
});
test('injected deadline accepts 5000 and refuses 5001 milliseconds',()=>{
  const clock=n=>{let first=true;return ()=>{if(first){first=false;return 0;}return n;};};
  assert.equal(evaluateConsent(policy(),capture(),{now:clock(5000)}).status,'pass');
  const r=evaluateConsent(policy(),capture(),{now:clock(5001)});assert.equal(r.status,'incomplete');assert.equal(r.findings[0].ruleId,'time-limit');
});
