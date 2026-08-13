import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";

const execFileAsync = promisify(execFile);
const dataDir = process.env.DRM_DATA_DIR ?? "/data";
const routesPath = `${dataDir}/routes.json`;

type ManagedRoute = {
  id: string;
  destination: string;
  gateway?: string | null;
  dev?: string | null;
  metric?: number | null;
  enabled: boolean;
};

async function ip(args:string[]) {
  const {stdout}=await execFileAsync("ip",args,{maxBuffer:1024*1024});
  return stdout;
}

async function readManagedRoutes():Promise<ManagedRoute[]> {
  await mkdir(dataDir,{recursive:true});
  try { return JSON.parse(await readFile(routesPath,"utf8")) as ManagedRoute[]; }
  catch { return []; }
}
async function saveManagedRoutes(routes:ManagedRoute[]) {
  await mkdir(dataDir,{recursive:true});
  await writeFile(routesPath,JSON.stringify(routes,null,2));
}

export async function getRoutingStatus() {
  const [routeRaw,addrRaw,linkRaw,managed] = await Promise.all([
    ip(["-j","route","show","table","main"]),
    ip(["-j","addr","show"]),
    ip(["-j","link","show"]),
    readManagedRoutes()
  ]);
  let ipForward=false;
  try { ipForward=(await readFile('/proc/sys/net/ipv4/ip_forward','utf8')).trim()==='1'; } catch {}
  return {
    ipForward,
    routes: JSON.parse(routeRaw),
    addresses: JSON.parse(addrRaw),
    links: JSON.parse(linkRaw),
    managedRoutes: managed
  };
}

export async function setIpForward(enabled:boolean) {
  await writeFile('/proc/sys/net/ipv4/ip_forward', enabled ? '1\n' : '0\n');
  return getRoutingStatus();
}

function validateRoute(input:any){
  if(!input.destination || typeof input.destination!=="string") throw new Error("Destination is required");
  if(!input.gateway && !input.dev) throw new Error("Gateway or interface is required");
  if(input.metric!=null && (!Number.isInteger(Number(input.metric)) || Number(input.metric)<0)) throw new Error("Metric must be >= 0");
}

async function applyOne(route:ManagedRoute){
  const args=["route","replace",route.destination];
  if(route.gateway) args.push("via",route.gateway);
  if(route.dev) args.push("dev",route.dev);
  if(route.metric!=null) args.push("metric",String(route.metric));
  await ip(args);
}

export async function addManagedRoute(input:any){
  validateRoute(input);
  const route:ManagedRoute={id:randomUUID(),destination:input.destination,gateway:input.gateway||null,dev:input.dev||null,metric:input.metric==null?null:Number(input.metric),enabled:true};
  await applyOne(route);
  const routes=await readManagedRoutes(); routes.push(route); await saveManagedRoutes(routes);
  return route;
}

export async function deleteManagedRoute(id:string){
  const routes=await readManagedRoutes();
  const route=routes.find(r=>r.id===id); if(!route) throw new Error("Route not found");
  const args=["route","del",route.destination];
  if(route.gateway) args.push("via",route.gateway);
  if(route.dev) args.push("dev",route.dev);
  try { await ip(args); } catch {}
  await saveManagedRoutes(routes.filter(r=>r.id!==id));
}

export async function restoreManagedRoutes(){
  const routes=await readManagedRoutes();
  for(const route of routes.filter(r=>r.enabled)){
    try { await applyOne(route); } catch(e){ console.warn('DRM route restore failed',route.destination,e); }
  }
}
