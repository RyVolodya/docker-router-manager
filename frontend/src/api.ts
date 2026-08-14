import type { Topology } from "./types";

let csrfToken = "";
export function setCsrfToken(token:string){ csrfToken=token; }

async function apiFetch(url:string, init:RequestInit={}) {
  const method=(init.method ?? "GET").toUpperCase();
  const headers=new Headers(init.headers ?? {});
  if(!["GET","HEAD","OPTIONS"].includes(method) && csrfToken) headers.set("X-CSRF-Token",csrfToken);
  const response=await fetch(url,{...init,headers,credentials:"same-origin"});
  if(!response.ok){
    if(response.status===401 && url!=="/api/auth/login") window.dispatchEvent(new Event("drm-auth-expired"));
    const text=await response.text();
    let message=text;
    try{message=JSON.parse(text).message ?? text;}catch{}
    const error=new Error(message) as Error & {status?:number;code?:string};
    error.status=response.status;
    try{error.code=JSON.parse(text).error;}catch{}
    throw error;
  }
  if(response.status===204)return null;
  const type=response.headers.get("content-type") ?? "";
  return type.includes("application/json") ? response.json() : response.text();
}

export async function login(username:string,password:string){
  const result=await apiFetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username,password})});
  setCsrfToken(result.csrfToken); return result;
}
export async function getMe(){const result=await apiFetch("/api/auth/me");setCsrfToken(result.csrfToken);return result;}
export async function logout(){await apiFetch("/api/auth/logout",{method:"POST"});setCsrfToken("");}
export async function changePassword(currentPassword:string,newPassword:string){return apiFetch("/api/auth/change-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({currentPassword,newPassword})});}
export const listManagementUsers=()=>apiFetch("/api/management/users");
export const addManagementUser=(body:any)=>apiFetch("/api/management/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const changeManagementRole=(id:string,role:string)=>apiFetch(`/api/management/users/${encodeURIComponent(id)}/role`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({role})});
export const resetManagementPassword=(id:string,password:string)=>apiFetch(`/api/management/users/${encodeURIComponent(id)}/reset-password`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password})});
export const removeManagementUser=(id:string)=>apiFetch(`/api/management/users/${encodeURIComponent(id)}`,{method:"DELETE"});

export async function getTopology(signal?: AbortSignal): Promise<Topology> {return apiFetch("/api/topology",{signal});}
export const getFirewallStatus=()=>apiFetch("/api/firewall/status");
export const createFirewallRule=(rule:any)=>apiFetch("/api/firewall/rules",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const removeFirewallRule=(id:string)=>apiFetch(`/api/firewall/rules/${encodeURIComponent(id)}`,{method:"DELETE"});
export const firewallAction=(action:"apply"|"disable"|"rollback")=>apiFetch(`/api/firewall/${action}`,{method:"POST"});
export const createPublishedPortRule=(rule:any)=>apiFetch("/api/firewall/published-port-rules",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const removePublishedPortRule=(id:string)=>apiFetch(`/api/firewall/published-port-rules/${encodeURIComponent(id)}`,{method:"DELETE"});
export const getNetworkStats=()=>apiFetch("/api/stats/network");
export const getRoutingStatus=()=>apiFetch("/api/routing/status");
export const setRoutingForward=(enabled:boolean)=>apiFetch("/api/routing/ip-forward",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled})});
export const setRoutingForward6=(enabled:boolean)=>apiFetch("/api/routing/ip-forward6",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled})});
export const createRoute=(route:any)=>apiFetch("/api/routing/routes",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(route)});
export const updateRoute=(id:string,route:any)=>apiFetch(`/api/routing/routes/${encodeURIComponent(id)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(route)});
export const removeRoute=(id:string)=>apiFetch(`/api/routing/routes/${encodeURIComponent(id)}`,{method:"DELETE"});
export const getWireGuard=()=>apiFetch("/api/wireguard/status");
export const createWgInterface=(body:any)=>apiFetch("/api/wireguard/interfaces",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const removeWgInterface=(name:string)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}`,{method:"DELETE"});
export const createWgPeer=(name:string,body:any)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
export const removeWgPeer=(name:string,id:string)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers/${encodeURIComponent(id)}`,{method:"DELETE"});
export const getWgClientConfig=(name:string,id:string)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers/${encodeURIComponent(id)}/config`);

export const getWgClientQr=(name:string,id:string)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/peers/${encodeURIComponent(id)}/qr`);

export const createHostInputRule=(rule:any)=>apiFetch("/api/firewall/host-input-rules",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(rule)});
export const removeHostInputRule=(id:string)=>apiFetch(`/api/firewall/host-input-rules/${encodeURIComponent(id)}`,{method:"DELETE"});
export const setWgAccessPolicy=(name:string,body:any)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/access`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});

export const setWgIpv6=(name:string,body:any)=>apiFetch(`/api/wireguard/interfaces/${encodeURIComponent(name)}/ipv6`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
