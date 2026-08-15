import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import type {
  FirewallAction,
  FirewallConfig,
  FirewallProtocol,
  FirewallRule,
  HostInputFirewallRule,
  PublishedPortFirewallRule
} from "./types.js";
import { getTopology, listNetworks } from "./dockerService.js";

const execFileAsync = promisify(execFile);
const dataDir = process.env.DRM_DATA_DIR ?? "/data";
const configPath = `${dataDir}/firewall.json`;
const backupPath = `${dataDir}/firewall.backup.json`;
const appliedPath = `${dataDir}/firewall.applied.json`;
const chain = "DRM-FIREWALL";
const inputChain = "DRM-INPUT";
const chain6 = "DRM6-FIREWALL";
const inputChain6 = "DRM6-INPUT";
const commentPrefix = "DRM:";

async function ip6tables(args: string[]) {
  return execFileAsync("ip6tables", ["-w", "5", ...args], { maxBuffer: 1024 * 1024 });
}

async function iptables(args: string[]) {
  return execFileAsync("iptables", ["-w", "5", ...args], {
    maxBuffer: 1024 * 1024
  });
}


async function conntrack(args: string[]) {
  return execFileAsync("conntrack", args, {
    maxBuffer: 1024 * 1024
  });
}

async function terminatePublishedPortConnections(config: FirewallConfig) {
  for (const rule of (config.publishedPortRules ?? []).filter(
    (r) => r.enabled && (r.action === "DROP" || r.action === "REJECT")
  )) {
    const args = [
      "-D",
      "-p", rule.protocol,
      "--orig-port-dst", String(rule.publishedPort)
    ];

    if (rule.hostIp && rule.hostIp !== "0.0.0.0" && rule.hostIp.includes(".")) {
      args.push("--orig-dst", rule.hostIp);
    }

    if (rule.sourceCidr && rule.sourceCidr !== "0.0.0.0/0") {
      args.push("--orig-src", rule.sourceCidr);
    }

    try {
      await conntrack(args);
    } catch (error: any) {
      const output = `${String(error?.stdout ?? "")}\n${String(error?.stderr ?? "")}`.toLowerCase();

      // conntrack commonly exits non-zero when there are no matching flows.
      // That is not a firewall failure.
      if (!output.includes("0 flow entries")) {
        console.warn(
          `DRM: conntrack cleanup failed for ${rule.protocol}/${rule.publishedPort}:`,
          error instanceof Error ? error.message : String(error)
        );
      }
    }
  }
}


function familyOfCidr(cidr: string): 4 | 6 {
  return cidr.includes(":") ? 6 : 4;
}
function normalizeFamily(value: any, fallback: 4 | 6 | "both" = 4): 4 | 6 | "both" {
  return value === 6 || value === "6" ? 6 : value === "both" ? "both" : value === 4 || value === "4" ? 4 : fallback;
}
function validCidr(cidr: string, family: 4 | 6) {
  if (!cidr || !cidr.includes("/")) return false;
  return family === 6 ? cidr.includes(":") : cidr.includes(".");
}
async function chainExists6(name:string) { try { await ip6tables(["-n","-L",name]); return true; } catch { return false; } }
async function ensureChain6(name:string, parent:string) {
  if (!(await chainExists6(name))) await ip6tables(["-N",name]);
  try { await ip6tables(["-C",parent,"-j",name]); } catch { await ip6tables(["-I",parent,"1","-j",name]); }
}
async function removeJump6(name:string,parent:string) {
  while(true){ try{await ip6tables(["-D",parent,"-j",name]);}catch{break;} }
}
async function chainExists() {
  try {
    await iptables(["-n", "-L", chain]);
    return true;
  } catch {
    return false;
  }
}

async function inputChainExists() {
  try { await iptables(["-n", "-L", inputChain]); return true; }
  catch { return false; }
}

async function ensureInputChain() {
  if (!(await inputChainExists())) await iptables(["-N", inputChain]);
  try { await iptables(["-C", "INPUT", "-j", inputChain]); }
  catch { await iptables(["-I", "INPUT", "1", "-j", inputChain]); }
}

async function removeInputJump() {
  while (true) {
    try { await iptables(["-D", "INPUT", "-j", inputChain]); }
    catch { break; }
  }
}


async function ensureChain() {
  if (!(await chainExists())) {
    await iptables(["-N", chain]);
  }

  // Ensure exactly one jump from DOCKER-USER and keep it first.
  try {
    await iptables(["-C", "DOCKER-USER", "-j", chain]);
  } catch {
    await iptables(["-I", "DOCKER-USER", "1", "-j", chain]);
  }
}

async function removeJump() {
  while (true) {
    try {
      await iptables(["-D", "DOCKER-USER", "-j", chain]);
    } catch {
      break;
    }
  }
}

export async function getFirewallConfig(): Promise<FirewallConfig> {
  await mkdir(dataDir, { recursive: true });
  try {
    const parsed = JSON.parse(await readFile(configPath, "utf8")) as FirewallConfig;
    return {
      ...parsed,
      rules: parsed.rules ?? [],
      publishedPortRules: parsed.publishedPortRules ?? [],
      hostInputRules: parsed.hostInputRules ?? []
    };
  } catch {
    return {
      enabled: false,
      rules: [],
      publishedPortRules: [],
      hostInputRules: [],
      updatedAt: new Date().toISOString()
    };
  }
}

async function saveConfig(config: FirewallConfig) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(configPath, JSON.stringify(config, null, 2));
}

async function saveBackup(config: FirewallConfig) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(backupPath, JSON.stringify(config, null, 2));
}

async function getBackup(): Promise<FirewallConfig | null> {
  try {
    const parsed = JSON.parse(await readFile(backupPath, "utf8")) as FirewallConfig;
    return {
      ...parsed,
      rules: parsed.rules ?? [],
      publishedPortRules: parsed.publishedPortRules ?? [],
      hostInputRules: parsed.hostInputRules ?? []
    };
  } catch {
    return null;
  }
}

async function saveApplied(config: FirewallConfig) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(appliedPath, JSON.stringify(config, null, 2));
}

async function getApplied(): Promise<FirewallConfig> {
  try {
    const parsed = JSON.parse(await readFile(appliedPath, "utf8")) as FirewallConfig;
    return {
      ...parsed,
      rules: parsed.rules ?? [],
      publishedPortRules: parsed.publishedPortRules ?? [],
      hostInputRules: parsed.hostInputRules ?? []
    };
  } catch {
    return {
      enabled: false,
      rules: [],
      publishedPortRules: [],
      hostInputRules: [],
      updatedAt: new Date(0).toISOString()
    };
  }
}

function validateRule(rule: Omit<FirewallRule, "id"> | FirewallRule) {
  if (!rule.sourceNetworkId || !rule.destinationNetworkId) {
    throw new Error("Source and destination networks are required");
  }
  if (rule.sourceNetworkId === rule.destinationNetworkId) {
    throw new Error("Source and destination networks must be different");
  }
  if (!["all", "tcp", "udp", "icmp", "icmpv6"].includes(rule.protocol)) {
    throw new Error("Unsupported protocol");
  }
  if (!["ACCEPT", "DROP", "REJECT"].includes(rule.action)) {
    throw new Error("Unsupported action");
  }
  if (rule.destinationPort != null) {
    if (!["tcp", "udp"].includes(rule.protocol)) {
      throw new Error("Ports are valid only for TCP or UDP");
    }
    if (!Number.isInteger(rule.destinationPort) || rule.destinationPort < 1 || rule.destinationPort > 65535) {
      throw new Error("Destination port must be 1..65535");
    }
  }
}

export async function addFirewallRule(input: {
  family?: 4 | 6 | "both";
  sourceNetworkId: string;
  destinationNetworkId: string;
  protocol: FirewallProtocol;
  destinationPort?: number | null;
  action: FirewallAction;
  enabled?: boolean;
  description?: string;
}) {
  validateRule({ ...input, enabled: input.enabled ?? true } as FirewallRule);
  const config = await getFirewallConfig();
  const rule: FirewallRule = {
    id: randomUUID(),
    family: normalizeFamily(input.family, 4),
    sourceNetworkId: input.sourceNetworkId,
    destinationNetworkId: input.destinationNetworkId,
    protocol: input.protocol,
    destinationPort: input.destinationPort ?? null,
    action: input.action,
    enabled: input.enabled ?? true,
    description: input.description?.trim() ?? ""
  };
  config.rules.push(rule);
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
  return rule;
}

export async function deleteFirewallRule(id: string) {
  const config = await getFirewallConfig();
  const before = config.rules.length;
  config.rules = config.rules.filter((r) => r.id !== id);
  if (before === config.rules.length) throw new Error("Rule not found");
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
}


function validatePublishedPortRule(rule: Omit<PublishedPortFirewallRule, "id"> | PublishedPortFirewallRule) {
  if (!rule.containerId || !rule.containerName) throw new Error("Container is required");
  if (!["tcp", "udp"].includes(rule.protocol)) throw new Error("Published port protocol must be TCP or UDP");
  if (!Number.isInteger(rule.publishedPort) || rule.publishedPort < 1 || rule.publishedPort > 65535) {
    throw new Error("Published port must be 1..65535");
  }
  if (!Number.isInteger(rule.containerPort) || rule.containerPort < 1 || rule.containerPort > 65535) {
    throw new Error("Container port must be 1..65535");
  }
  if (!["ACCEPT", "DROP", "REJECT"].includes(rule.action)) throw new Error("Unsupported action");
  const family = normalizeFamily(rule.family, familyOfCidr(rule.sourceCidr));
  if (family === "both" || !validCidr(rule.sourceCidr, family)) throw new Error("Source CIDR does not match address family");
}

export async function addPublishedPortRule(input: {
  family?: 4 | 6;
  containerId: string;
  containerName: string;
  protocol: "tcp" | "udp";
  publishedPort: number;
  hostIp: string;
  containerPort: number;
  sourceCidr?: string;
  action: FirewallAction;
  enabled?: boolean;
  description?: string;
}) {
  const rule: PublishedPortFirewallRule = {
    id: randomUUID(),
    family: normalizeFamily(input.family, (input.hostIp||"").includes(":") ? 6 : 4) as 4|6,
    containerId: input.containerId,
    containerName: input.containerName,
    protocol: input.protocol,
    publishedPort: input.publishedPort,
    hostIp: input.hostIp || "0.0.0.0",
    containerPort: input.containerPort,
    sourceCidr: input.sourceCidr || "0.0.0.0/0",
    action: input.action,
    enabled: input.enabled ?? true,
    description: input.description?.trim() ?? ""
  };
  validatePublishedPortRule(rule);

  // Verify this mapping currently exists in Docker.
  const topology = await getTopology();
  const container = topology.containers.find((c) => c.id === rule.containerId);
  const exists = container?.ports.some(
    (p) =>
      p.protocol === rule.protocol &&
      p.port === rule.containerPort &&
      p.published.some(
        (b) => b.hostPort === rule.publishedPort && (b.hostIp || "0.0.0.0") === rule.hostIp
      )
  );
  if (!exists) throw new Error("Selected Docker published port mapping no longer exists");

  const config = await getFirewallConfig();
  config.publishedPortRules.push(rule);
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
  return rule;
}

export async function deletePublishedPortRule(id: string) {
  const config = await getFirewallConfig();
  const before = config.publishedPortRules.length;
  config.publishedPortRules = config.publishedPortRules.filter((r) => r.id !== id);
  if (before === config.publishedPortRules.length) throw new Error("Published port rule not found");
  config.updatedAt = new Date().toISOString();
  await saveConfig(config);
}


function validateHostInputRule(rule: Omit<HostInputFirewallRule, "id"> | HostInputFirewallRule) {
  if (!rule.interfaceName) throw new Error("Interface is required");
  if (!["all","tcp","udp","icmp","icmpv6"].includes(rule.protocol)) throw new Error("Unsupported protocol");
  if (!["ACCEPT","DROP","REJECT"].includes(rule.action)) throw new Error("Unsupported action");
  const family=normalizeFamily(rule.family, familyOfCidr(rule.sourceCidr));
  if(family!=="both" && !validCidr(rule.sourceCidr,family)) throw new Error("Source CIDR does not match address family");
  if (rule.destinationPort != null) {
    if (!["tcp","udp"].includes(rule.protocol)) throw new Error("Destination port requires TCP or UDP");
    if (!Number.isInteger(rule.destinationPort) || rule.destinationPort < 1 || rule.destinationPort > 65535) throw new Error("Destination port must be 1..65535");
  }
}

export async function addHostInputRule(input: {
  family?:4|6|"both"; interfaceName?: string; localAddress?: string|null; protocol:FirewallProtocol;
  destinationPort?: number|null; sourceCidr?: string; action:FirewallAction; enabled?:boolean; description?:string;
}) {
  const rule:HostInputFirewallRule={
    id:randomUUID(), family:normalizeFamily(input.family,4), interfaceName:input.interfaceName||"*", localAddress:input.localAddress||null,
    protocol:input.protocol, destinationPort:input.destinationPort??null, sourceCidr:input.sourceCidr||"0.0.0.0/0",
    action:input.action, enabled:input.enabled??true, description:input.description?.trim()??""
  };
  validateHostInputRule(rule);
  const config=await getFirewallConfig();
  config.hostInputRules.push(rule); config.updatedAt=new Date().toISOString(); await saveConfig(config); return rule;
}

export async function deleteHostInputRule(id:string) {
  const config=await getFirewallConfig();
  const before=config.hostInputRules.length;
  config.hostInputRules=config.hostInputRules.filter(r=>r.id!==id);
  if(before===config.hostInputRules.length) throw new Error("Host INPUT rule not found");
  config.updatedAt=new Date().toISOString(); await saveConfig(config);
}

async function buildInputRuleCommands(config:FirewallConfig, family:4) {
  const commands:string[][]=[["-A",inputChain,"-m","conntrack","--ctstate","ESTABLISHED,RELATED","-m","comment","--comment",`${commentPrefix}input-state`,"-j","ACCEPT"]];
  for(const rule of (config.hostInputRules??[]).filter(r=>r.enabled && [4,"both"].includes(normalizeFamily(r.family,4) as any))){
    validateHostInputRule(rule);
    const args=["-A",inputChain,"-s",rule.sourceCidr];
    if(rule.interfaceName!=="*") args.push("-i",rule.interfaceName);
    if(rule.localAddress && rule.localAddress.includes(".")) args.push("-d",rule.localAddress);
    if(rule.protocol!=="all") args.push("-p",rule.protocol==="icmpv6"?"icmp":rule.protocol);
    if(rule.destinationPort!=null) args.push("--dport",String(rule.destinationPort));
    args.push("-m","comment","--comment",`${commentPrefix}input:${rule.id}`,"-j",rule.action); commands.push(args);
  }
  commands.push(["-A",inputChain,"-m","comment","--comment",`${commentPrefix}input-return`,"-j","RETURN"]); return commands;
}
async function buildInputRuleCommands6(config:FirewallConfig) {
  const commands:string[][]=[["-A",inputChain6,"-m","conntrack","--ctstate","ESTABLISHED,RELATED","-m","comment","--comment","DRM6:input-state","-j","ACCEPT"]];
  // Essential ICMPv6 control traffic: ND, RA/RS and Packet Too Big must not be accidentally broken.
  for(const type of ["1","2","3","4","133","134","135","136"]) commands.push(["-A",inputChain6,"-p","ipv6-icmp","--icmpv6-type",type,"-m","comment","--comment","DRM6:essential-icmpv6","-j","ACCEPT"]);
  for(const rule of (config.hostInputRules??[]).filter(r=>r.enabled && [6,"both"].includes(normalizeFamily(r.family,4) as any))){
    const source=normalizeFamily(rule.family,4)==="both" ? "::/0" : rule.sourceCidr;
    const args=["-A",inputChain6,"-s",source];
    if(rule.interfaceName!=="*") args.push("-i",rule.interfaceName);
    if(rule.localAddress && rule.localAddress.includes(":")) args.push("-d",rule.localAddress);
    if(rule.protocol!=="all") args.push("-p",rule.protocol==="icmpv6"||rule.protocol==="icmp"?"ipv6-icmp":rule.protocol);
    if(rule.destinationPort!=null) args.push("--dport",String(rule.destinationPort));
    args.push("-m","comment","--comment",`DRM6:input:${rule.id}`,"-j",rule.action); commands.push(args);
  }
  commands.push(["-A",inputChain6,"-m","comment","--comment","DRM6:input-return","-j","RETURN"]); return commands;
}

async function getHostNetworkRefs() {
  let interfaces:Array<{name:string;addresses:string[]}>=[]; let defaultWanInterface:string|null=null;
  let hostPorts:Array<{protocol:"tcp"|"udp";listenAddress:string;port:number}>=[];
  try{
    const {stdout}=await execFileAsync("ip",["-j","address","show"],{maxBuffer:1024*1024});
    interfaces=(JSON.parse(stdout) as any[]).filter(x=>x.ifname&&x.ifname!=="lo").map(x=>({
      name:String(x.ifname), addresses:(x.addr_info??[]).filter((a:any)=>a.family==="inet"||a.family==="inet6").map((a:any)=>`${a.local}/${a.prefixlen}`)
    })).sort((a,b)=>a.name.localeCompare(b.name));
  }catch{}
  try{
    const {stdout}=await execFileAsync("ip",["-j","route","show","default"],{maxBuffer:1024*1024});
    defaultWanInterface=(JSON.parse(stdout) as any[])[0]?.dev??null;
  }catch{}
  try{
    const {stdout}=await execFileAsync("ss",["-H","-lntu","-n"],{maxBuffer:1024*1024});
    const refs=new Map<string,{protocol:"tcp"|"udp";listenAddress:string;port:number}>();
    for(const line of stdout.split("\n").filter(Boolean)){
      const fields=line.trim().split(/\s+/); const proto=fields[0]?.startsWith("tcp")?"tcp":fields[0]?.startsWith("udp")?"udp":null;
      if(!proto)continue; const local=fields[4]??""; let address=""; let port=0;
      const v6=local.match(/^\[([^\]]+)\]:(\d+)$/);
      if(v6){address=v6[1];port=Number(v6[2]);}
      else {const pos=local.lastIndexOf(":"); if(pos>=0){address=local.slice(0,pos)||"*";port=Number(local.slice(pos+1));}}
      if(!Number.isInteger(port)||port<1)continue;
      refs.set(`${proto}|${address}|${port}`,{protocol:proto,listenAddress:address,port});
    }
    hostPorts=[...refs.values()].sort((a,b)=>a.port-b.port||a.protocol.localeCompare(b.protocol));
  }catch{}
  return {interfaces,defaultWanInterface,hostPorts};
}

function cidrs(subnets: Array<{ subnet: string | null }>, family:4|6) {
  return subnets.map(s=>s.subnet).filter((x):x is string=>Boolean(x && (family===6 ? x.includes(":") : x.includes("."))));
}

async function buildRuleCommands(config: FirewallConfig, family:4|6) {
  const networks=await listNetworks(); const byId=new Map(networks.map(n=>[n.id,n]));
  const targetChain=family===6?chain6:chain; const prefix=family===6?"DRM6:":commentPrefix;
  const commands:string[][]=[["-A",targetChain,"-m","conntrack","--ctstate","ESTABLISHED,RELATED","-m","comment","--comment",`${prefix}state`,"-j","ACCEPT"]];
  for(const rule of (config.publishedPortRules??[]).filter(r=>r.enabled && normalizeFamily(r.family,(r.hostIp||"").includes(":")?6:4)===family)){
    validatePublishedPortRule(rule);
    const args=["-A",targetChain,"-s",rule.sourceCidr,"-p",rule.protocol,"-m","conntrack","--ctstate","NEW","--ctorigdstport",String(rule.publishedPort)];
    if(rule.hostIp && !["0.0.0.0","::"].includes(rule.hostIp) && (family===6?rule.hostIp.includes(":"):rule.hostIp.includes("."))) args.push("--ctorigdst",rule.hostIp);
    args.push("-m","comment","--comment",`${prefix}published:${rule.id}`,"-j",rule.action); commands.push(args);
  }
  for(const rule of config.rules.filter(r=>r.enabled && [family,"both"].includes(normalizeFamily(r.family,4) as any))){
    validateRule(rule); const src=byId.get(rule.sourceNetworkId),dst=byId.get(rule.destinationNetworkId);
    if(!src||!dst) throw new Error(`Network for rule ${rule.id} no longer exists`);
    const srcs=cidrs(src.subnets,family),dsts=cidrs(dst.subnets,family);
    // A "both" rule applies to whichever families both networks actually provide.
    if(!srcs.length||!dsts.length) continue;
    for(const source of srcs) for(const destination of dsts){
      const args=["-A",targetChain,"-s",source,"-d",destination];
      if(rule.protocol!=="all") args.push("-p",family===6 && (rule.protocol==="icmp"||rule.protocol==="icmpv6")?"ipv6-icmp":rule.protocol==="icmpv6"?"icmp":rule.protocol);
      if(rule.destinationPort!=null) args.push("--dport",String(rule.destinationPort));
      if(rule.action==="ACCEPT") args.push("-m","conntrack","--ctstate","NEW");
      args.push("-m","comment","--comment",`${prefix}${rule.id}`,"-j",rule.action); commands.push(args);
    }
  }
  commands.push(["-A",targetChain,"-m","comment","--comment",`${prefix}return`,"-j","RETURN"]); return commands;
}

async function render(config: FirewallConfig) {
  await ensureChain(); await ensureInputChain();
  await ensureChain6(chain6,"DOCKER-USER"); await ensureChain6(inputChain6,"INPUT");
  await iptables(["-F",chain]); await iptables(["-F",inputChain]); await ip6tables(["-F",chain6]); await ip6tables(["-F",inputChain6]);
  if(!config.enabled){await removeJump();await removeInputJump();await removeJump6(chain6,"DOCKER-USER");await removeJump6(inputChain6,"INPUT");return;}
  try{await iptables(["-C","DOCKER-USER","-j",chain]);}catch{await iptables(["-I","DOCKER-USER","1","-j",chain]);}
  try{await iptables(["-C","INPUT","-j",inputChain]);}catch{await iptables(["-I","INPUT","1","-j",inputChain]);}
  try{await ip6tables(["-C","DOCKER-USER","-j",chain6]);}catch{await ip6tables(["-I","DOCKER-USER","1","-j",chain6]);}
  try{await ip6tables(["-C","INPUT","-j",inputChain6]);}catch{await ip6tables(["-I","INPUT","1","-j",inputChain6]);}
  for(const args of await buildRuleCommands(config,4)) await iptables(args);
  for(const args of await buildInputRuleCommands(config,4)) await iptables(args);
  for(const args of await buildRuleCommands(config,6)) await ip6tables(args);
  for(const args of await buildInputRuleCommands6(config)) await ip6tables(args);
}

export async function applyFirewall() {
  const draft = await getFirewallConfig();
  const previousApplied = await getApplied();
  await saveBackup(previousApplied);

  const next: FirewallConfig = {
    ...draft,
    rules: draft.rules.map((r) => ({ ...r })),
    publishedPortRules: (draft.publishedPortRules ?? []).map((r) => ({ ...r })),
    hostInputRules: (draft.hostInputRules ?? []).map((r) => ({ ...r })),
    enabled: true,
    updatedAt: new Date().toISOString()
  };

  try {
    await render(next);
    await saveApplied(next);
    await saveConfig(next);

    // Make DROP/REJECT apply to already-established published-port sessions.
    await terminatePublishedPortConnections(next);

    return getFirewallStatus();
  } catch (error) {
    try {
      await render(previousApplied);
      await saveApplied(previousApplied);
    } catch {
      // Preserve the original apply error.
    }
    throw error;
  }
}

export async function disableFirewall() {
  const draft = await getFirewallConfig();
  const previousApplied = await getApplied();
  await saveBackup(previousApplied);

  const next: FirewallConfig = {
    ...draft,
    rules: draft.rules.map((r) => ({ ...r })),
    publishedPortRules: (draft.publishedPortRules ?? []).map((r) => ({ ...r })),
    hostInputRules: (draft.hostInputRules ?? []).map((r) => ({ ...r })),
    enabled: false,
    updatedAt: new Date().toISOString()
  };

  await render(next);
  await saveApplied(next);
  await saveConfig(next);
  return getFirewallStatus();
}

export async function rollbackFirewall() {
  const backup = await getBackup();
  if (!backup) throw new Error("No rollback snapshot exists");

  const restored: FirewallConfig = {
    ...backup,
    rules: backup.rules.map((r) => ({ ...r })),
    publishedPortRules: (backup.publishedPortRules ?? []).map((r) => ({ ...r })),
    hostInputRules: (backup.hostInputRules ?? []).map((r) => ({ ...r })),
    updatedAt: new Date().toISOString()
  };

  await render(restored);
  await saveApplied(restored);
  await saveConfig(restored);
  await terminatePublishedPortConnections(restored);
  return getFirewallStatus();
}

export async function getFirewallStatus() {
  const config = await getFirewallConfig();
  const applied = await getApplied();
  const pendingChanges =
    JSON.stringify({
      enabled: config.enabled,
      rules: config.rules,
      publishedPortRules: config.publishedPortRules ?? [],
      hostInputRules: config.hostInputRules ?? []
    }) !==
    JSON.stringify({
      enabled: applied.enabled,
      rules: applied.rules,
      publishedPortRules: applied.publishedPortRules ?? [],
      hostInputRules: applied.hostInputRules ?? []
    });

  let installedRules: string[] = [];
  let installedInputRules: string[] = [];
  let chainPresent = false;
  let jumpPresent = false;
  let inputChainPresent = false;
  let inputJumpPresent = false;
  let error: string | null = null;
  let installedRules6:string[]=[]; let installedInputRules6:string[]=[]; let chainPresent6=false; let jumpPresent6=false; let inputChainPresent6=false; let inputJumpPresent6=false;

  try {
    chainPresent = await chainExists();
    if (chainPresent) {
      const { stdout } = await iptables(["-S", chain]);
      installedRules = stdout
        .split("\n")
        .map((x: string) => x.trim())
        .filter(Boolean);
    }
    try {
      await iptables(["-C", "DOCKER-USER", "-j", chain]);
      jumpPresent = true;
    } catch {
      jumpPresent = false;
    }
    inputChainPresent=await inputChainExists();
    if(inputChainPresent){
      const {stdout}=await iptables(["-S",inputChain]);
      installedInputRules=stdout.split("\n").map((x:string)=>x.trim()).filter(Boolean);
    }
    try{await iptables(["-C","INPUT","-j",inputChain]);inputJumpPresent=true;}catch{inputJumpPresent=false;}

    chainPresent6=await chainExists6(chain6); inputChainPresent6=await chainExists6(inputChain6);
    if(chainPresent6){const {stdout}=await ip6tables(["-S",chain6]);installedRules6=stdout.split("\n").map(x=>x.trim()).filter(Boolean);}
    if(inputChainPresent6){const {stdout}=await ip6tables(["-S",inputChain6]);installedInputRules6=stdout.split("\n").map(x=>x.trim()).filter(Boolean);}
    try{await ip6tables(["-C","DOCKER-USER","-j",chain6]);jumpPresent6=true;}catch{}
    try{await ip6tables(["-C","INPUT","-j",inputChain6]);inputJumpPresent6=true;}catch{}
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const [networks, topology] = await Promise.all([listNetworks(), getTopology()]);
  const networkRefs = networks
    .filter((n) => n.driver === "bridge")
    .map((n) => ({
      id: n.id,
      name: n.name,
      subnets: n.subnets.map((s) => s.subnet).filter((x): x is string => Boolean(x))
    }))
    .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));

  const publishedPortRefs = topology.containers
    .flatMap((container) =>
      container.ports.flatMap((port) =>
        port.published
          .filter(() => port.protocol === "tcp" || port.protocol === "udp")
          .map((binding) => ({
            containerId: container.id,
            containerName: container.name,
            protocol: port.protocol as "tcp" | "udp",
            publishedPort: binding.hostPort,
            hostIp: binding.hostIp || "0.0.0.0",
            containerPort: port.port
          }))
      )
    )
    .filter((port) => Number.isInteger(port.publishedPort) && port.publishedPort > 0)
    .sort((a, b) =>
      a.containerName.localeCompare(b.containerName) ||
      a.publishedPort - b.publishedPort ||
      a.protocol.localeCompare(b.protocol) ||
      a.hostIp.localeCompare(b.hostIp)
    );

  const hostRefs=await getHostNetworkRefs();

  return {
    engine: "iptables + ip6tables",
    managedChain: `${chain} / ${chain6}`,
    config,
    applied,
    pendingChanges,
    lastAppliedAt: applied.updatedAt === new Date(0).toISOString() ? null : applied.updatedAt,
    networkRefs,
    publishedPortRefs,
    hostInterfaces:hostRefs.interfaces,
    defaultWanInterface:hostRefs.defaultWanInterface,
    hostPortRefs:hostRefs.hostPorts,
    runtime: {
      chainPresent,
      jumpPresent,
      installedRules,
      inputChainPresent,
      inputJumpPresent,
      installedInputRules,
      chainPresent6,jumpPresent6,installedRules6,inputChainPresent6,inputJumpPresent6,installedInputRules6,
      error
    }
  };
}
