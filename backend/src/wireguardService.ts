import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import QRCode from "qrcode";

const dataDir=process.env.DRM_DATA_DIR ?? "/data";
const wgDir=`${dataDir}/wireguard`;
const statePath=`${wgDir}/state.json`;

type Peer={id:string;name:string;publicKey:string;privateKey?:string;serverAllowedIps:string[];clientAllowedIps:string[];clientAddress?:string;endpoint?:string;endpointHost?:string;endpointPort?:number;dns?:string;persistentKeepalive:number};
type WgInterface={name:string;address:string;listenPort:number;mtu:number;privateKey:string;publicKey:string;peers:Peer[]};
type WgState={interfaces:WgInterface[]};

async function run(cmd:string,args:string[],stdin?:string){
  return await new Promise<string>((resolve,reject)=>{
    const child=spawn(cmd,args,{stdio:["pipe","pipe","pipe"]});
    let stdout="";
    let stderr="";

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");

    child.stdout.on("data",(chunk:string)=>{stdout+=chunk;});
    child.stderr.on("data",(chunk:string)=>{stderr+=chunk;});

    child.on("error",reject);
    child.on("close",(code)=>{
      if(code===0){
        resolve(stdout.trim());
      }else{
        reject(new Error(`${cmd} ${args.join(" ")} failed with code ${code}: ${stderr.trim()}`));
      }
    });

    if(stdin!==undefined){
      child.stdin.write(stdin);
    }
    child.stdin.end();
  });
}
async function load():Promise<WgState>{ await mkdir(wgDir,{recursive:true}); try{return JSON.parse(await readFile(statePath,'utf8')) as WgState}catch{return{interfaces:[]}} }
async function save(state:WgState){await mkdir(wgDir,{recursive:true});await writeFile(statePath,JSON.stringify(state,null,2),{mode:0o600});}
function validName(name:string){if(!/^[a-zA-Z0-9_=+.-]{1,15}$/.test(name)) throw new Error('Invalid interface name');}
async function genKeyPair(){const privateKey=await run('wg',['genkey']);const publicKey=await run('wg',['pubkey'],privateKey+'\n');return{privateKey,publicKey};}
async function keyFile(name:string,key:string){const path=`${wgDir}/${name}.key`;await writeFile(path,key+'\n',{mode:0o600});return path;}


function endpointString(peer:Peer){
  if(peer.endpointHost && peer.endpointPort){
    const host=peer.endpointHost.includes(":") && !peer.endpointHost.startsWith("[") ? `[${peer.endpointHost}]` : peer.endpointHost;
    return `${host}:${peer.endpointPort}`;
  }
  return peer.endpoint;
}

function endpointParts(peer:Peer){
  if(peer.endpointHost && peer.endpointPort) return {endpointHost:peer.endpointHost,endpointPort:peer.endpointPort};
  const raw=peer.endpoint ?? "";
  const ipv6=raw.match(/^\[([^\]]+)\]:(\d+)$/);
  if(ipv6) return {endpointHost:ipv6[1],endpointPort:Number(ipv6[2])};
  const pos=raw.lastIndexOf(":");
  if(pos>0 && /^\d+$/.test(raw.slice(pos+1))) return {endpointHost:raw.slice(0,pos),endpointPort:Number(raw.slice(pos+1))};
  return {endpointHost:raw||undefined,endpointPort:undefined};
}

async function applyInterface(item:WgInterface){
  validName(item.name);
  try{await run('ip',['link','show','dev',item.name]);}catch{await run('ip',['link','add','dev',item.name,'type','wireguard']);}
  const kf=await keyFile(item.name,item.privateKey);
  await run('wg',['set',item.name,'private-key',kf,'listen-port',String(item.listenPort)]);
  await run('ip',['address','replace',item.address,'dev',item.name]);
  await run('ip',['link','set','dev',item.name,'mtu',String(item.mtu),'up']);
  for(const peer of item.peers){
    const args=['set',item.name,'peer',peer.publicKey];
    if(peer.serverAllowedIps.length) args.push('allowed-ips',peer.serverAllowedIps.join(','));
    const endpoint=endpointString(peer); if(endpoint) args.push('endpoint',endpoint);
    if(peer.persistentKeepalive>0) args.push('persistent-keepalive',String(peer.persistentKeepalive));
    await run('wg',args);
  }
}

export async function restoreWireGuard(){const st=await load();for(const i of st.interfaces){try{await applyInterface(i)}catch(e){console.warn('DRM WG restore failed',i.name,e)}}}

export async function getWireGuardStatus(){
  const state=await load(); let runtime:any[]=[];
  try{const raw=await run('wg',['show','all','dump']);runtime=raw?raw.split('\n').map(x=>x.split('\t')):[]}catch{}
  return {interfaces:state.interfaces.map(i=>({name:i.name,address:i.address,listenPort:i.listenPort,mtu:i.mtu,publicKey:i.publicKey,peers:i.peers.map(p=>({...p,...endpointParts(p),privateKey:undefined}))})),runtime};
}

export async function createWireGuardInterface(input:any){
  const name=String(input.name||'wg0');validName(name);
  const state=await load(); if(state.interfaces.some(i=>i.name===name)) throw new Error('Interface already exists');
  if(!input.address) throw new Error('Address is required');
  const keys=await genKeyPair();
  const item:WgInterface={name,address:String(input.address),listenPort:Number(input.listenPort||51820),mtu:Number(input.mtu||1420),privateKey:keys.privateKey,publicKey:keys.publicKey,peers:[]};
  await applyInterface(item);state.interfaces.push(item);await save(state);return {name:item.name,publicKey:item.publicKey};
}

export async function deleteWireGuardInterface(name:string){
  validName(name);const state=await load();
  try{await run('ip',['link','del','dev',name]);}catch{}
  await rm(`${wgDir}/${name}.key`,{force:true});
  state.interfaces=state.interfaces.filter(i=>i.name!==name);await save(state);
}

export async function addWireGuardPeer(iface:string,input:any){
  validName(iface);const state=await load();const item=state.interfaces.find(i=>i.name===iface);if(!item)throw new Error('Interface not found');
  const keys=input.publicKey ? {publicKey:String(input.publicKey),privateKey:undefined} : await genKeyPair();
  const serverAllowedIps=(input.serverAllowedIps||[]).map(String).filter(Boolean);if(!serverAllowedIps.length)throw new Error('Server AllowedIPs are required');
  const endpointHost=input.endpointHost?String(input.endpointHost).trim():undefined;
  const endpointPort=input.endpointPort?Number(input.endpointPort):undefined;
  if(endpointPort!==undefined && (!Number.isInteger(endpointPort)||endpointPort<1||endpointPort>65535)) throw new Error('Endpoint port must be 1..65535');
  const peer:Peer={id:randomUUID(),name:String(input.name||'peer'),publicKey:keys.publicKey,privateKey:keys.privateKey,serverAllowedIps,clientAllowedIps:(input.clientAllowedIps||[]).map(String).filter(Boolean),clientAddress:input.clientAddress?String(input.clientAddress):undefined,endpoint:input.endpoint?String(input.endpoint):undefined,endpointHost,endpointPort,dns:input.dns?String(input.dns).trim():undefined,persistentKeepalive:Number(input.persistentKeepalive||0)};
  item.peers.push(peer);await applyInterface(item);await save(state);return {id:peer.id,publicKey:peer.publicKey,clientConfigAvailable:Boolean(peer.privateKey)};
}

export async function deleteWireGuardPeer(iface:string,id:string){
  const state=await load();const item=state.interfaces.find(i=>i.name===iface);if(!item)throw new Error('Interface not found');const peer=item.peers.find(p=>p.id===id);if(!peer)throw new Error('Peer not found');
  try{await run('wg',['set',iface,'peer',peer.publicKey,'remove']);}catch{}
  item.peers=item.peers.filter(p=>p.id!==id);await save(state);
}

export async function getClientConfig(iface:string,id:string){
  const state=await load();const item=state.interfaces.find(i=>i.name===iface);if(!item)throw new Error('Interface not found');const peer=item.peers.find(p=>p.id===id);if(!peer)throw new Error('Peer not found');if(!peer.privateKey)throw new Error('Client private key is not stored for this peer');if(!peer.clientAddress)throw new Error('Client address is missing');if(!endpointString(peer))throw new Error('Server endpoint is missing');
  const lines=['[Interface]',`PrivateKey = ${peer.privateKey}`,`Address = ${peer.clientAddress}`];if(peer.dns)lines.push(`DNS = ${peer.dns}`);lines.push('','[Peer]',`PublicKey = ${item.publicKey}`,`Endpoint = ${endpointString(peer)}`,`AllowedIPs = ${(peer.clientAllowedIps.length?peer.clientAllowedIps:['0.0.0.0/0']).join(', ')}`);if(peer.persistentKeepalive>0)lines.push(`PersistentKeepalive = ${peer.persistentKeepalive}`);return lines.join('\n')+'\n';
}

export async function getClientConfigQrSvg(iface:string,id:string){
  const config=await getClientConfig(iface,id);
  return await QRCode.toString(config,{
    type:"svg",
    errorCorrectionLevel:"M",
    margin:2,
    width:320
  });
}
