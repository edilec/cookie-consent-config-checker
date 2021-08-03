#!/usr/bin/env node
import {readFile,realpath,stat} from 'node:fs/promises';
import {resolve,relative,isAbsolute,sep} from 'node:path';
import {evaluateConsent,incomplete,LIMITS} from '../src/index.mjs';

const args=process.argv.slice(2);
if(args.length===1&&args[0]==='--help'){
  process.stdout.write('Usage: cookie-consent-config-checker --root DIR --policy FILE --capture FILE [--human]\nChecks exported consent policy and captured events; not legal advice.\n');
}else{
  let root,policyName,captureName,human=false;
  try{
    for(let i=0;i<args.length;i++){
      const key=args[i];
      if(key==='--human'){if(human)throw Error('duplicate');human=true;continue;}
      if(!['--root','--policy','--capture'].includes(key)||i+1>=args.length||args[i+1].startsWith('--'))throw Error('option');
      const value=args[++i];
      if(key==='--root'){if(root)throw Error('duplicate');root=value;}
      if(key==='--policy'){if(policyName)throw Error('duplicate');policyName=value;}
      if(key==='--capture'){if(captureName)throw Error('duplicate');captureName=value;}
    }
    if(!root||!policyName||!captureName||isAbsolute(policyName)||isAbsolute(captureName))throw Error('required');
    root=await realpath(root);
    if(!(await stat(root)).isDirectory())throw Error('root');
  }catch{process.stderr.write('Invalid configuration. Use --help.\n');process.exit(2);}
  const inside=path=>{const rel=relative(root,path);return rel!==''&&rel!=='..'&&!rel.startsWith(`..${sep}`)&&!isAbsolute(rel);};
  async function document(name,file,limit){
    try{
      const path=await realpath(resolve(root,name));
      if(!inside(path)||!(await stat(path)).isFile())throw Error('unreadable');
      const metadata=await stat(path);
      if(metadata.size>limit)return {error:incomplete('byte-limit',file)};
      const bytes=await readFile(path,{signal:AbortSignal.timeout(LIMITS.milliseconds)});
      if(bytes.length>limit)return {error:incomplete('byte-limit',file)};
      return {value:JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes))};
    }catch{return {error:incomplete('input-unreadable',file)};}
  }
  const p=await document(policyName,'@policy',LIMITS.policyBytes);
  const c=await document(captureName,'@capture',LIMITS.captureBytes);
  const result=p.error||c.error||evaluateConsent(p.value,c.value);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if(human)process.stderr.write(`Consent check: ${result.status}; ${result.summary.checked} records checked.\n`);
  process.exitCode=result.status==='pass'?0:result.status==='fail'?1:2;
}
