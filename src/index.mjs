export const TOOL_ID='cookie-consent-config-checker';
export const LIMITS=Object.freeze({policyBytes:262144,captureBytes:1048576,categories:100,scripts:1000,events:10000,depth:16,milliseconds:5000});
export const RULE_SEVERITY=Object.freeze({'input-unreadable':'warning','input-invalid':'warning','export-incomplete':'warning','byte-limit':'warning','record-limit':'warning','depth-limit':'warning','time-limit':'warning','category-duplicate':'warning','script-duplicate':'warning','event-invalid':'warning','script-unobserved':'warning','category-mismatch':'error','mapping-mismatch':'error','optional-default-granted':'error','required-default-denied':'error','script-before-consent':'error'});
const MESSAGES=Object.freeze({'input-unreadable':'Input could not be read, decoded, or parsed.','input-invalid':'Consent document has unsupported or invalid fields.','export-incomplete':'Consent evidence does not assert complete coverage.','byte-limit':'Input exceeds its declared byte limit.','record-limit':'Consent record count exceeds its declared limit.','depth-limit':'JSON nesting exceeds depth 16.','time-limit':'Evaluation exceeded 5000 milliseconds.','category-duplicate':'Category identity is duplicated.','script-duplicate':'Script identity is duplicated.','event-invalid':'Captured event refers to unusable or unknown evidence.','script-unobserved':'Optional script load was not observed in the fixture.','category-mismatch':'Captured category configuration differs from policy.','mapping-mismatch':'Captured script mapping differs from policy.','optional-default-granted':'Optional category defaults to granted.','required-default-denied':'Required category defaults to denied.','script-before-consent':'Optional script loaded without granted consent.'});
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const id=x=>typeof x==='string'&&/^[a-z][a-z0-9-]{0,63}$/.test(x);
function finding(ruleId,file,pointer=''){if(!Object.hasOwn(RULE_SEVERITY,ruleId))throw Error('unknown rule');return {ruleId,severity:RULE_SEVERITY[ruleId],message:MESSAGES[ruleId],location:{file,pointer}};}
function report(findings,checked=0){findings.sort((a,b)=>cmp(a.location.file,b.location.file)||cmp(a.location.pointer,b.location.pointer)||cmp(a.ruleId,b.ruleId));const status=findings.some(f=>f.severity==='warning')?'incomplete':findings.length?'fail':'pass';return {schemaVersion:'1',tool:TOOL_ID,status,summary:{checked,errors:findings.filter(f=>f.severity==='error').length,warnings:findings.filter(f=>f.severity==='warning').length},findings};}
export function incomplete(ruleId,file){return report([finding(ruleId,file)]);}
function tooDeep(value){const stack=[[value,0]];while(stack.length){const [item,depth]=stack.pop();if(depth>LIMITS.depth)return true;if(item&&typeof item==='object')for(const child of Object.values(item))stack.push([child,depth+1]);}return false;}
const category=x=>object(x)&&id(x.id)&&typeof x.required==='boolean'&&typeof x.defaultGranted==='boolean';
const script=x=>object(x)&&id(x.id)&&id(x.category);
function validDocument(x,captured){return object(x)&&x.schemaVersion==='1'&&(x.complete===undefined||typeof x.complete==='boolean')&&Array.isArray(x.categories)&&x.categories.length>0&&Array.isArray(x.scripts)&&x.scripts.length>0&&(!captured||Array.isArray(x.events));}
function indexed(values,key,file,rule,findings){const map=new Map();for(const [i,item] of values.entries()){if(map.has(item[key]))findings.push(finding(rule,file,`/${rule==='category-duplicate'?'categories':'scripts'}/${i}`));else map.set(item[key],item);}return map;}
function equivalent(a,b,fields){return a.size===b.size&&[...a].every(([key,item])=>{const other=b.get(key);return other&&fields.every(field=>item[field]===other[field]);});}

export function evaluateConsent(policy,capture,{now=()=>performance.now()}={}){
  const start=now(),findings=[];const timed=()=>now()-start>LIMITS.milliseconds;
  if(tooDeep(policy))findings.push(finding('depth-limit','@policy'));
  if(tooDeep(capture))findings.push(finding('depth-limit','@capture'));
  if(findings.length)return report(findings);
  if(!validDocument(policy,false))findings.push(finding('input-invalid','@policy'));
  if(!validDocument(capture,true))findings.push(finding('input-invalid','@capture'));
  if(findings.length)return report(findings);
  if(policy.complete!==true)findings.push(finding('export-incomplete','@policy','/complete'));
  if(capture.complete!==true)findings.push(finding('export-incomplete','@capture','/complete'));
  if(findings.length)return report(findings);
  for(const [file,doc] of [['@policy',policy],['@capture',capture]]){
    if(doc.categories.length>LIMITS.categories||doc.scripts.length>LIMITS.scripts||(file==='@capture'&&doc.events.length>LIMITS.events))findings.push(finding('record-limit',file));
    if(doc.categories.some(x=>!category(x))||doc.scripts.some(x=>!script(x)))findings.push(finding('input-invalid',file));
  }
  if(findings.length)return report(findings);
  const pCategories=indexed(policy.categories,'id','@policy','category-duplicate',findings);
  const cCategories=indexed(capture.categories,'id','@capture','category-duplicate',findings);
  const pScripts=indexed(policy.scripts,'id','@policy','script-duplicate',findings);
  const cScripts=indexed(capture.scripts,'id','@capture','script-duplicate',findings);
  if(findings.length)return report(findings);
  for(const [file,scripts,categories] of [['@policy',policy.scripts,pCategories],['@capture',capture.scripts,cCategories]]){
    for(const [i,item] of scripts.entries())if(!categories.has(item.category))findings.push(finding('input-invalid',file,`/scripts/${i}/category`));
  }
  if(findings.length)return report(findings);
  if(!equivalent(pCategories,cCategories,['required','defaultGranted']))findings.push(finding('category-mismatch','@capture','/categories'));
  if(!equivalent(pScripts,cScripts,['category']))findings.push(finding('mapping-mismatch','@capture','/scripts'));
  if(findings.length)return report(findings);
  for(const [i,item] of policy.categories.entries()){
    if(!item.required&&item.defaultGranted)findings.push(finding('optional-default-granted','@policy',`/categories/${i}/defaultGranted`));
    if(item.required&&!item.defaultGranted)findings.push(finding('required-default-denied','@policy',`/categories/${i}/defaultGranted`));
  }
  if(timed())return incomplete('time-limit','@capture');
  const granted=new Map(policy.categories.map(x=>[x.id,x.defaultGranted]));
  const loaded=new Set();
  let checked=policy.scripts.length;
  for(const [i,event] of capture.events.entries()){
    if(timed())return incomplete('time-limit','@capture');
    if(!object(event)){findings.push(finding('event-invalid','@capture',`/events/${i}`));continue;}
    if(event.type==='grant'||event.type==='revoke'){
      if(!id(event.category)||!pCategories.has(event.category)){findings.push(finding('event-invalid','@capture',`/events/${i}`));continue;}
      granted.set(event.category,event.type==='grant');checked++;continue;
    }
    if(event.type==='load'){
      const mapped=pScripts.get(event.script);
      if(!id(event.script)||!mapped){findings.push(finding('event-invalid','@capture',`/events/${i}`));continue;}
      loaded.add(event.script);
      checked++;
      if(!pCategories.get(mapped.category).required&&!granted.get(mapped.category))findings.push(finding('script-before-consent','@capture',`/events/${i}`));
      continue;
    }
    findings.push(finding('event-invalid','@capture',`/events/${i}`));
  }
  for(const [i,item] of policy.scripts.entries())if(!pCategories.get(item.category).required&&!loaded.has(item.id))findings.push(finding('script-unobserved','@policy',`/scripts/${i}`));
  if(timed())return incomplete('time-limit','@capture');
  return report(findings,checked);
}
