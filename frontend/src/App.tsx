import { useEffect, useMemo, useState } from "react";
import {
  Activity, Boxes, Container, GitBranch, LayoutDashboard, Network,
  RefreshCw, Route, Search, Server, Shield, Wifi, CircleDot, Plug, Trash2, KeyRound, Waypoints, Plus, UserCog, LogOut, Moon, Sun, Download, QrCode
} from "lucide-react";
import { Background, Controls, Edge, MarkerType, MiniMap, Node, ReactFlow, useNodesState } from "@xyflow/react";
import { addManagementUser, changeManagementRole, changePassword, createFirewallRule, createPublishedPortRule, firewallAction, getFirewallStatus, getMe, getNetworkStats, getTopology, listManagementUsers, login, logout, removeFirewallRule, removeManagementUser, removePublishedPortRule, resetManagementPassword, createRoute, createWgInterface, createWgPeer, getRoutingStatus, getWgClientConfig, getWgClientQr, getWireGuard, removeRoute, removeWgInterface, removeWgPeer, setRoutingForward } from "./api";
import type { DockerContainer, DockerNetwork, FirewallStatus, NetworkStatsResponse, RoutingStatus, Topology, WireGuardStatus } from "./types";

type Page = "dashboard" | "networks" | "containers" | "ports" | "topology" | "firewall" | "routing" | "wireguard" | "management";

type AuthUser = {id:string;username:string;role:"administrator"|"operator"|"viewer";mustChangePassword:boolean;createdAt:string;updatedAt:string;lastLoginAt:string|null;disabled:boolean};

const navigation = [
  { id: "dashboard" as Page, label: "Dashboard", icon: LayoutDashboard },
  { id: "networks" as Page, label: "Networks", icon: Network },
  { id: "containers" as Page, label: "Containers", icon: Container },
  { id: "ports" as Page, label: "Ports", icon: Plug },
  { id: "topology" as Page, label: "Topology", icon: GitBranch },
  { id: "firewall" as Page, label: "Firewall", icon: Shield },
  { id: "routing" as Page, label: "Routing", icon: Waypoints },
  { id: "wireguard" as Page, label: "WireGuard", icon: KeyRound },
  { id: "management" as Page, label: "Management", icon: UserCog }
];

function MainApp({auth,onAuthChange,onLogout,theme,onToggleTheme}:{auth:AuthUser;onAuthChange:(u:AuthUser)=>void;onLogout:()=>void;theme:"dark"|"light";onToggleTheme:()=>void}) {
  const [page, setPage] = useState<Page>("dashboard");
  const [data, setData] = useState<Topology | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [firewallStatus, setFirewallStatus] = useState<FirewallStatus | null>(null);
  const [trafficRates, setTrafficRates] = useState<Record<string,{rxRate:number;txRate:number;rxBytes:number;txBytes:number}>>({});

  async function refresh() {
    setLoading(true);
    try {
      const [result, fw] = await Promise.all([
        getTopology(),
        getFirewallStatus()
      ]);
      setData(result);
      setFirewallStatus(fw);
      setLastUpdate(new Date());
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 10000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    let previous: NetworkStatsResponse | null = null;
    async function pollTraffic() {
      try {
        const current = await getNetworkStats() as NetworkStatsResponse;
        if (previous) {
          const prevById = new Map(previous.containers.map(c => [c.id, c]));
          const elapsed = Math.max(0.25,(new Date(current.generatedAt).getTime()-new Date(previous.generatedAt).getTime())/1000);
          const next: Record<string,{rxRate:number;txRate:number;rxBytes:number;txBytes:number}> = {};
          for (const c of current.containers) { const prev=prevById.get(c.id); next[c.id]={rxRate:prev?Math.max(0,(c.rxBytes-prev.rxBytes)/elapsed):0,txRate:prev?Math.max(0,(c.txBytes-prev.txBytes)/elapsed):0,rxBytes:c.rxBytes,txBytes:c.txBytes}; }
          setTrafficRates(next);
        }
        previous=current;
      } catch {}
    }
    pollTraffic();
    const timer=window.setInterval(pollTraffic,2000);
    return ()=>window.clearInterval(timer);
  }, []);

  const filteredNetworks = useMemo(() => {
    const q = query.trim().toLowerCase();
    const stable = [...(data?.networks ?? [])].sort((a,b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    if (!q) return stable;
    return stable.filter(n =>
      [n.name, n.driver, ...n.subnets.flatMap(s => [s.subnet ?? "", s.gateway ?? ""])]
        .some(v => v.toLowerCase().includes(q))
    );
  }, [data, query]);

  const filteredContainers = useMemo(() => {
    const q = query.trim().toLowerCase();
    const stable = [...(data?.containers ?? [])].sort((a,b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    if (!q) return stable;
    return stable.filter(c =>
      [
        c.name, c.image, c.state,
        ...c.networks.flatMap(n => [n.networkName, n.ipv4Address ?? ""]),
        ...c.ports.flatMap(p => [
          p.containerPort,
          ...p.published.map(x => `${x.hostIp}:${x.hostPort}`)
        ])
      ].some(v => v.toLowerCase().includes(q))
    );
  }, [data, query]);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><img src="/drm-mark.svg" alt="DRM" /></div>
          <div className="brand-text"><strong>Docker Router</strong><span>Manager</span></div>
        </div>

        <nav>
          {navigation.map(item => {
            const Icon = item.icon;
            return (
              <button key={item.id}
                className={page === item.id ? "nav-item active" : "nav-item"}
                onClick={() => { setPage(item.id); setQuery(""); }}>
                <Icon size={18}/>{item.label}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="engine-card">
            <span className={error ? "status-dot bad" : "status-dot"} />
            <div><strong>{error ? "Docker API error" : "Docker Engine"}</strong>
              <span>{error ? "Disconnected" : "Connected"}</span></div>
          </div>
          <button className="theme-toggle" onClick={onToggleTheme} title={theme==="dark"?"Switch to light theme":"Switch to dark theme"}>
            <span className="theme-toggle-icon">{theme==="dark"?<Sun size={15}/>:<Moon size={15}/>}</span>
            <span className="theme-toggle-text">{theme==="dark"?"Light theme":"Dark theme"}</span>
          </button>
          <div className="sidebar-user"><strong>{auth.username}</strong><span>{auth.role}</span><button onClick={onLogout} title="Logout"><LogOut size={14}/></button></div>
          <div className="version">DRM v0.8.5</div>
        </div>
      </aside>

      <main className="main">
        <header>
          <div><span className="eyebrow">INFRASTRUCTURE</span>
            <h1>{navigation.find(n => n.id === page)?.label}</h1></div>
          <div className="header-actions">
            {["networks","containers","ports"].includes(page) && (
              <label className="search"><Search size={16}/>
                <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search..."/></label>
            )}
            <div className="sync">
              <span>{lastUpdate ? `Updated ${lastUpdate.toLocaleTimeString()}` : "Not synced"}</span>
              <button onClick={refresh} disabled={loading}><RefreshCw size={17} className={loading ? "spin" : ""}/></button>
            </div>
          </div>
        </header>

        {error && <div className="error-banner"><Shield size={18}/><div><strong>Cannot reach backend</strong><span>{error}</span></div></div>}

        {page === "dashboard" && <Dashboard data={data} trafficRates={trafficRates}/>}
        {page === "networks" && <Networks networks={filteredNetworks}/>}
        {page === "containers" && <Containers containers={filteredContainers}/>}
        {page === "ports" && <Ports containers={filteredContainers} firewall={firewallStatus}/>}
        {page === "topology" && <TopologyView data={data} firewall={firewallStatus}/>}
        {page === "firewall" && <FirewallEngine/>}
        {page === "routing" && <RoutingPage/>}
        {page === "wireguard" && <WireGuardPage topology={data}/>}
        {page === "management" && <ManagementPage auth={auth} onAuthChange={onAuthChange}/>}
      </main>
    </div>
  );
}


function LoginScreen({onAuthenticated}:{onAuthenticated:(user:AuthUser)=>void}){
  const [username,setUsername]=useState("admin");
  const [password,setPassword]=useState("");
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  async function submit(e:React.FormEvent){e.preventDefault();setBusy(true);setError("");try{const result=await login(username,password);onAuthenticated(result.user);}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  return <div className="auth-page"><form className="auth-card" onSubmit={submit}>
    <div className="auth-brand"><div className="brand-mark"><img src="/drm-mark.svg" alt="DRM" /></div><div><strong>Docker Router Manager</strong><span>Secure management access</span></div></div>
    <h1>Sign in</h1><p>Authenticate to manage Docker networking, firewall, routing and VPN.</p>
    {error&&<div className="auth-error">{error}</div>}
    <label><span>Username</span><input autoComplete="username" value={username} onChange={e=>setUsername(e.target.value)} /></label>
    <label><span>Password</span><input autoComplete="current-password" type="password" value={password} onChange={e=>setPassword(e.target.value)} autoFocus /></label>
    <button className="btn primary auth-submit" disabled={busy}>{busy?"Signing in…":"Sign in"}</button>
    <small>Bootstrap credentials: admin / admin. A password change is mandatory after the first login.</small>
  </form></div>;
}

function ForcedPasswordChange({auth,onChanged,onLogout}:{auth:AuthUser;onChanged:(u:AuthUser)=>void;onLogout:()=>void}){
  const [current,setCurrent]=useState("");const [next,setNext]=useState("");const [confirm,setConfirm]=useState("");const [error,setError]=useState("");const [busy,setBusy]=useState(false);
  async function submit(e:React.FormEvent){e.preventDefault();if(next!==confirm){setError("Passwords do not match");return;}setBusy(true);setError("");try{await changePassword(current,next);const me=await getMe();onChanged(me.user);}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  return <div className="auth-page"><form className="auth-card" onSubmit={submit}>
    <div className="auth-brand"><div className="brand-mark"><img src="/drm-mark.svg" alt="DRM" /></div><div><strong>Password change required</strong><span>{auth.username}</span></div></div>
    <h1>Create a new password</h1><p>The bootstrap password cannot be used to access DRM. Use at least 8 characters.</p>
    {error&&<div className="auth-error">{error}</div>}
    <label><span>Current password</span><input type="password" autoComplete="current-password" value={current} onChange={e=>setCurrent(e.target.value)}/></label>
    <label><span>New password</span><input type="password" autoComplete="new-password" minLength={8} value={next} onChange={e=>setNext(e.target.value)}/></label>
    <label><span>Confirm new password</span><input type="password" autoComplete="new-password" minLength={8} value={confirm} onChange={e=>setConfirm(e.target.value)}/></label>
    <button className="btn primary auth-submit" disabled={busy}>{busy?"Updating…":"Change password"}</button>
    <button type="button" className="auth-link" onClick={onLogout}>Sign out</button>
  </form></div>;
}

function ManagementPage({auth,onAuthChange}:{auth:AuthUser;onAuthChange:(u:AuthUser)=>void}){
  const [current,setCurrent]=useState("");const [next,setNext]=useState("");const [confirm,setConfirm]=useState("");
  const [users,setUsers]=useState<AuthUser[]>([]);const [message,setMessage]=useState("");const [error,setError]=useState("");
  const [newUser,setNewUser]=useState({username:"",password:"",role:"viewer"});
  async function loadUsers(){if(auth.role!=="administrator")return;try{setUsers(await listManagementUsers());}catch(e){setError(e instanceof Error?e.message:String(e));}}
  useEffect(()=>{loadUsers();},[auth.role]);
  async function ownPassword(e:React.FormEvent){e.preventDefault();setError("");setMessage("");if(next!==confirm){setError("Passwords do not match");return;}try{await changePassword(current,next);const me=await getMe();onAuthChange(me.user);setCurrent("");setNext("");setConfirm("");setMessage("Password changed successfully");}catch(e){setError(e instanceof Error?e.message:String(e));}}
  async function create(){setError("");try{await addManagementUser(newUser);setNewUser({username:"",password:"",role:"viewer"});await loadUsers();setMessage("User created; password change will be required at first login");}catch(e){setError(e instanceof Error?e.message:String(e));}}
  async function role(id:string,role:string){try{await changeManagementRole(id,role);await loadUsers();}catch(e){setError(e instanceof Error?e.message:String(e));}}
  async function reset(id:string,username:string){const password=window.prompt(`Temporary password for ${username} (min 8 characters):`);if(!password)return;try{await resetManagementPassword(id,password);await loadUsers();setMessage(`${username} must change password at next login`);}catch(e){setError(e instanceof Error?e.message:String(e));}}
  async function remove(id:string,username:string){if(!window.confirm(`Delete user ${username}?`))return;try{await removeManagementUser(id);await loadUsers();}catch(e){setError(e instanceof Error?e.message:String(e));}}
  return <div className="management-stack">
    {error&&<div className="error-banner"><Shield size={18}/><div><strong>Management error</strong><span>{error}</span></div></div>}
    {message&&<div className="management-success">{message}</div>}
    <div className="panel"><PanelTitle title="My account" subtitle={`${auth.username} · ${auth.role}`}/><form className="password-form" onSubmit={ownPassword}>
      <label><span>Current password</span><input type="password" value={current} onChange={e=>setCurrent(e.target.value)}/></label>
      <label><span>New password</span><input type="password" minLength={8} value={next} onChange={e=>setNext(e.target.value)}/></label>
      <label><span>Confirm password</span><input type="password" minLength={8} value={confirm} onChange={e=>setConfirm(e.target.value)}/></label>
      <button className="btn primary">Change password</button>
    </form></div>
    {auth.role==="administrator"&&<>
      <div className="panel"><PanelTitle title="Add user" subtitle="New accounts must change their temporary password at first login"/><div className="user-builder">
        <label><span>Username</span><input value={newUser.username} onChange={e=>setNewUser({...newUser,username:e.target.value})}/></label>
        <label><span>Temporary password</span><input type="password" minLength={8} value={newUser.password} onChange={e=>setNewUser({...newUser,password:e.target.value})}/></label>
        <label><span>Role</span><select value={newUser.role} onChange={e=>setNewUser({...newUser,role:e.target.value})}><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="administrator">Administrator</option></select></label>
        <button className="btn add-rule" onClick={create}>Add user</button>
      </div></div>
      <div className="table-panel"><div className="users-table-head"><span>User</span><span>Role</span><span>Password</span><span>Last login</span><span>Actions</span></div>
      {users.map(u=><div className="users-table-row" key={u.id}><div><strong>{u.username}</strong><small>{u.username==="admin"?"Built-in administrator":u.id}</small></div>
        <select value={u.role} disabled={u.username==="admin"} onChange={e=>role(u.id,e.target.value)}><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="administrator">Administrator</option></select>
        <span className={u.mustChangePassword?"pill warning":"pill green"}>{u.mustChangePassword?"CHANGE REQUIRED":"SET"}</span>
        <span>{u.lastLoginAt?new Date(u.lastLoginAt).toLocaleString():"Never"}</span>
        <div className="user-actions"><button className="btn secondary" onClick={()=>reset(u.id,u.username)}>Reset password</button><button className="icon-danger" disabled={u.username==="admin"} onClick={()=>remove(u.id,u.username)}><Trash2 size={15}/></button></div>
      </div>)}</div>
    </>}
  </div>;
}

function AuthenticatedApp(){
  const [auth,setAuth]=useState<AuthUser|null>(null);const [checking,setChecking]=useState(true);
  const [theme,setTheme]=useState<"dark"|"light">(()=>localStorage.getItem("drm-theme")==="light"?"light":"dark");
  useEffect(()=>{document.documentElement.dataset.theme=theme;localStorage.setItem("drm-theme",theme);},[theme]);
  const toggleTheme=()=>setTheme(current=>current==="dark"?"light":"dark");
  useEffect(()=>{
    getMe().then(r=>setAuth(r.user)).catch(()=>setAuth(null)).finally(()=>setChecking(false));
    const expired=()=>setAuth(null); window.addEventListener("drm-auth-expired",expired);
    return()=>window.removeEventListener("drm-auth-expired",expired);
  },[]);
  async function signOut(){try{await logout();}catch{}setAuth(null);}
  if(checking)return <div className="auth-page"><div className="auth-loading">Loading DRM…</div></div>;
  if(!auth)return <LoginScreen onAuthenticated={setAuth}/>;
  if(auth.mustChangePassword)return <ForcedPasswordChange auth={auth} onChanged={setAuth} onLogout={signOut}/>;
  return <MainApp auth={auth} onAuthChange={setAuth} onLogout={signOut} theme={theme} onToggleTheme={toggleTheme}/>;
}

function Dashboard({ data, trafficRates }: { data: Topology | null; trafficRates: Record<string,{rxRate:number;txRate:number;rxBytes:number;txBytes:number}> }) {
  const endpoints = data?.networks.reduce((n,x) => n+x.containers.length,0) ?? 0;
  const published = data?.containers.reduce((n,c) =>
    n + c.ports.reduce((m,p) => m + p.published.length,0), 0) ?? 0;
  const stats = [
    {label:"Networks",value:data?.networkCount ?? "—",icon:Network,hint:"Docker networks"},
    {label:"Containers",value:data?.containerCount ?? "—",icon:Boxes,hint:`${data?.runningContainerCount ?? 0} running`},
    {label:"Endpoints",value:endpoints,icon:CircleDot,hint:"Network attachments"},
    {label:"Published ports",value:published,icon:Plug,hint:"Host port mappings"}
  ];
  return <>
    <section className="stats-grid">
      {stats.map(({label,value,icon:Icon,hint}) =>
        <article className="stat-card" key={label}>
          <div className="icon-box"><Icon size={19}/></div><span className="stat-label">{label}</span>
          <strong className="stat-value">{value}</strong><span className="stat-hint">{hint}</span>
        </article>)}
    </section>
    <section className="two-col">
      <div className="panel"><PanelTitle title="Network overview" subtitle="Live Docker Engine data"/>
        <div className="network-list">{[...(data?.networks ?? [])].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id)).slice(0,6).map(n=><NetworkRow network={n} key={n.id}/>)}
        {!data?.networks.length && <Empty text="No network data yet"/>}</div>
      </div>
      <div className="panel"><PanelTitle title="Containers & ports" subtitle="Primary address and published services"/>
        <div className="container-list">{[...(data?.containers ?? [])].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id)).slice(0,7).map(c=>
          <div className="container-row" key={c.id}>
            <div className="container-icon"><Container size={17}/></div>
            <div className="grow"><strong>{c.name}</strong><span>{portSummary(c)}</span></div>
            <div className="right-meta"><span className={c.state==="running"?"pill green":"pill"}>{c.state}</span>
            <code>{c.networks[0]?.ipv4Address || "—"}</code></div>
          </div>)}
        {!data?.containers.length && <Empty text="No container data yet"/>}</div>
      </div>
    </section>
    <section className="panel live-traffic-panel">
      <PanelTitle title="Live container traffic" subtitle="Docker network I/O, refreshed every 2 seconds"/>
      <div className="traffic-table-head"><span>Container</span><span>RX / sec</span><span>TX / sec</span><span>Total RX</span><span>Total TX</span></div>
      {[...(data?.containers ?? [])].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id)).map(c=>{ const t=trafficRates[c.id]; return <div className="traffic-table-row" key={c.id}><div className="name-cell"><div className="container-icon"><Activity size={15}/></div><div><strong>{c.name}</strong><span>{c.networks.map(n=>n.ipv4Address).filter(Boolean).join(" · ") || "No IPv4"}</span></div></div><strong className="traffic-rx">{formatRate(t?.rxRate ?? 0)}</strong><strong className="traffic-tx">{formatRate(t?.txRate ?? 0)}</strong><span>{formatBytes(t?.rxBytes ?? 0)}</span><span>{formatBytes(t?.txBytes ?? 0)}</span></div>; })}
      {!data?.containers.length && <Empty text="No container traffic data"/>}
    </section>
  </>;
}

function Networks({networks}:{networks:DockerNetwork[]}) {
  return <section className="cards">{networks.map(network=>
    <article className="network-card" key={network.id}>
      <div className="network-card-head"><div className="network-symbol"><Network size={20}/></div>
        <div className="grow"><strong>{network.name}</strong><span>{network.id.slice(0,12)}</span></div>
        <span className="pill blue">{network.driver}</span></div>
      <div className="network-details">
        <Metric label="Subnet" value={network.subnets[0]?.subnet || "—"}/>
        <Metric label="Gateway" value={network.subnets[0]?.gateway || "—"}/>
        <Metric label="Containers" value={String(network.containers.length)}/>
        <Metric label="Scope" value={network.scope}/>
      </div>
      <div className="endpoint-block"><span className="section-label">ATTACHED ENDPOINTS</span>
        {network.containers.length ? network.containers.map(e=>
          <div className="endpoint" key={e.id}><span className="status-dot"/><strong>{e.name}</strong><code>{e.ipv4Address || "—"}</code></div>)
        : <span className="muted">No attached containers</span>}
      </div>
    </article>)}
    {!networks.length && <Empty text="No matching networks"/>}
  </section>;
}

function Containers({containers}:{containers:DockerContainer[]}) {
  return <div className="table-panel">
    <div className="table-head ports-aware"><span>Container</span><span>Image</span><span>Network</span><span>IPv4</span><span>Ports</span><span>Status</span></div>
    {containers.map(c=><div className="table-row ports-aware" key={c.id}>
      <div className="name-cell"><div className="container-icon"><Container size={16}/></div>
        <div><strong>{c.name}</strong><span>{c.id.slice(0,12)}</span></div></div>
      <span className="truncate">{c.image}</span>
      <span>{c.networks[0]?.networkName || "—"}</span>
      <code>{c.networks[0]?.ipv4Address || "—"}</code>
      <div className="port-mini">{c.ports.length ? c.ports.slice(0,3).map(p=><span key={p.containerPort}>{p.containerPort}</span>) : <span>—</span>}</div>
      <span><span className={c.state==="running"?"pill green":"pill"}>{c.state}</span></span>
    </div>)}
    {!containers.length && <Empty text="No matching containers"/>}
  </div>;
}

function Ports({containers,firewall}:{containers:DockerContainer[];firewall:FirewallStatus|null}) {
  const rows = containers.flatMap(c => c.ports.map(p => ({c,p})));

  function publishedRuleState(c:DockerContainer, p:DockerContainer["ports"][number]) {
    const rules=firewall?.config.publishedPortRules ?? [];
    const matching=p.published.flatMap(binding => rules.filter(r => r.enabled && r.containerId===c.id && r.protocol===p.protocol && r.publishedPort===binding.hostPort && r.containerPort===p.port && (r.hostIp===binding.hostIp || (!r.hostIp && !binding.hostIp))));
    const blocks=matching.filter(r=>r.action==="DROP" || r.action==="REJECT"); const accepts=matching.filter(r=>r.action==="ACCEPT");
    if(blocks.some(r=>r.sourceCidr==="0.0.0.0/0")) return {state:"blocked" as const,detail:"All sources blocked"};
    if(blocks.length) return {state:"restricted" as const,detail:`Blocked: ${blocks.map(r=>r.sourceCidr).join(", ")}`};
    if(accepts.some(r=>r.sourceCidr==="0.0.0.0/0")) return {state:"allowed" as const,detail:"Explicit allow"};
    if(accepts.length) return {state:"restricted" as const,detail:`Allowed only: ${accepts.map(r=>r.sourceCidr).join(", ")}`};
    return {state:"open" as const,detail:"No firewall rule"};
  }

  return <div className="table-panel">
    <div className="port-table-head"><span>Container</span><span>Container IP</span><span>Internal port</span><span>Published on host</span><span>Firewall</span></div>

    {rows.map(({c,p},i)=>{
      const policy=publishedRuleState(c,p);
      const state=policy.state;
      const portClass=state==="blocked" ? "port-number blocked" : state==="allowed" ? "port-number allowed" : state==="restricted" ? "port-number restricted" : "port-number open";

      return <div className="port-table-row" key={`${c.id}-${p.containerPort}-${i}`}>
        <div className="name-cell">
          <div className="container-icon"><Plug size={15}/></div>
          <div><strong>{c.name}</strong><span>{c.image}</span></div>
        </div>

        <code>{c.networks[0]?.ipv4Address || "—"}</code>

        <code className={portClass}>{p.containerPort}</code>

        <div className="published-list">
          {p.published.length ? p.published.map((x,j)=>
            <code className={portClass} key={j}>
              {formatHostIp(x.hostIp)}:{x.hostPort} → {p.containerPort}
            </code>)
            : <span className="pill">not published</span>}
        </div>

        <div className="port-firewall-state"><span className={state==="blocked" ? "pill danger" : state==="allowed" ? "pill green" : state==="restricted" ? "pill warning" : "pill blue"}>{state==="blocked" ? "BLOCKED" : state==="allowed" ? "ALLOW" : state==="restricted" ? "RESTRICTED" : "NO RULE"}</span><small>{policy.detail}</small></div>
      </div>;
    })}

    {!rows.length && <Empty text="No exposed or published ports"/>}
  </div>;
}

function FirewallEngine() {
  const [status,setStatus]=useState<FirewallStatus|null>(null);
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  const [source,setSource]=useState("");
  const [destination,setDestination]=useState("");
  const [protocol,setProtocol]=useState<"all"|"tcp"|"udp"|"icmp">("all");
  const [port,setPort]=useState("");
  const [action,setAction]=useState<"ACCEPT"|"DROP"|"REJECT">("ACCEPT");
  const [description,setDescription]=useState("");
  const [publishedKey,setPublishedKey]=useState("");
  const [publishedSource,setPublishedSource]=useState("0.0.0.0/0");
  const [publishedAction,setPublishedAction]=useState<"DROP"|"REJECT"|"ACCEPT">("DROP");
  const [publishedDescription,setPublishedDescription]=useState("");

  async function load() {
    try { setStatus(await getFirewallStatus()); setMessage(""); }
    catch(e){ setMessage(e instanceof Error ? e.message : String(e)); }
  }

  useEffect(()=>{ load(); const timer=window.setInterval(load,10000); return()=>window.clearInterval(timer); },[]);

  const networks=status?.networkRefs ?? [];
  const byId=new Map(networks.map(n=>[n.id,n]));

  async function addRule() {
    if(!source || !destination){setMessage("Select source and destination networks");return;}
    setBusy(true);
    try{
      await createFirewallRule({
        sourceNetworkId:source,
        destinationNetworkId:destination,
        protocol,
        destinationPort:port ? Number(port) : null,
        action,
        description
      });
      setDescription(""); setPort(""); await load();
    }catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  async function remove(id:string) {
    setBusy(true);
    try{await removeFirewallRule(id);await load();}
    catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  async function doAction(which:"apply"|"disable"|"rollback"){
    setBusy(true);
    try{setStatus(await firewallAction(which));setMessage("");}
    catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  const publishedRefs=status?.publishedPortRefs ?? [];
  const selectedPublished=publishedRefs.find((x)=>
    `${x.containerId}|${x.hostIp}|${x.publishedPort}|${x.protocol}|${x.containerPort}`===publishedKey
  );

  async function addPublishedRule(){
    if(!selectedPublished){setMessage("Select a published Docker port");return;}
    setBusy(true);
    try{
      await createPublishedPortRule({
        ...selectedPublished,
        sourceCidr:publishedSource || "0.0.0.0/0",
        action:publishedAction,
        description:publishedDescription
      });
      setPublishedDescription("");
      await load();
    }catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  async function removePublished(id:string){
    setBusy(true);
    try{await removePublishedPortRule(id);await load();}
    catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }

  return <div className="firewall-stack">
    <div className="panel firewall-global">
      <div className="firewall-global-left">
        <div className="engine-line">
          <div>
            <span className="stat-label">Firewall Engine</span>
            <strong className="firewall-state">{status?.config.enabled ? "Enabled" : "Disabled"}</strong>
            <span className="stat-hint">{status?.engine ?? "—"} · {status?.managedChain ?? "—"}</span>
          </div>

          <button
            className={status?.config.enabled ? "engine-toggle on" : "engine-toggle"}
            disabled={busy || !status}
            onClick={()=>doAction(status?.config.enabled ? "disable" : "apply")}
            title={status?.config.enabled ? "Disable Firewall Engine" : "Enable Firewall Engine"}
          >
            <span className="toggle-knob"></span>
            <span className="toggle-label">{status?.config.enabled ? "ON" : "OFF"}</span>
          </button>
        </div>

        <div className="engine-meta">
          <span className={status?.pendingChanges ? "change-state pending" : "change-state applied"}>
            {status?.pendingChanges ? "Pending changes" : "Applied"}
          </span>
          <span className="last-applied">
            Last applied: {status?.lastAppliedAt ? new Date(status.lastAppliedAt).toLocaleString() : "Never"}
          </span>
          <span className="runtime-jump">
            DOCKER-USER jump: {status?.runtime.jumpPresent ? "active" : "inactive"}
          </span>
        </div>
      </div>

      <div className="firewall-global-actions">
        <button className="btn secondary" disabled={busy} onClick={()=>doAction("rollback")}>Rollback</button>
        <button className="btn primary" disabled={busy || !status?.pendingChanges} onClick={()=>doAction("apply")}>Apply changes</button>
      </div>
    </div>

    {message && <div className="error-banner"><Shield size={18}/><div><strong>Firewall error</strong><span>{message}</span></div></div>}

    <div className="panel">
      <div className="firewall-titlebar">
        <PanelTitle title="Inbound / Published Ports" subtitle="Control access from outside to Docker host published ports"/>
      </div>

      <div className="session-policy-note">
        <Shield size={15}/>
        <div>
          <strong>Existing sessions are terminated on Apply</strong>
          <span>For DROP/REJECT, DRM deletes matching conntrack sessions for this published port.</span>
        </div>
      </div>

      <div className="published-rule-builder">
        <label><span>Published Docker port</span>
          <select value={publishedKey} onChange={e=>setPublishedKey(e.target.value)}>
            <option value="">Select published port</option>
            {publishedRefs.map((x,i)=>{
              const key=`${x.containerId}|${x.hostIp}|${x.publishedPort}|${x.protocol}|${x.containerPort}`;
              return <option key={`${key}-${i}`} value={key}>
                {x.hostIp}:{x.publishedPort}/{x.protocol} → {x.containerName}:{x.containerPort}
              </option>;
            })}
          </select>
        </label>
        <label><span>Source CIDR</span>
          <input value={publishedSource} onChange={e=>setPublishedSource(e.target.value)} placeholder="0.0.0.0/0"/>
        </label>
        <label><span>Action</span>
          <select value={publishedAction} onChange={e=>setPublishedAction(e.target.value as any)}>
            <option value="DROP">DROP</option><option value="REJECT">REJECT</option><option value="ACCEPT">ACCEPT</option>
          </select>
        </label>
        <label><span>Description</span>
          <input value={publishedDescription} onChange={e=>setPublishedDescription(e.target.value)} placeholder="Optional"/>
        </label>
        <button className="btn add-rule" disabled={busy} onClick={addPublishedRule}>Add rule</button>
      </div>

      <div className="published-policy-list">
        {(status?.config.publishedPortRules ?? []).map(rule=>
          <div className="published-policy-row" key={rule.id}>
            <div><strong>{rule.hostIp}:{rule.publishedPort}/{rule.protocol}</strong>
              <small>→ {rule.containerName}:{rule.containerPort}</small></div>
            <code>{rule.sourceCidr}</code>
            <span className={rule.action==="ACCEPT"?"pill green":rule.action==="DROP"?"pill danger":"pill"}>{rule.action}</span>
            <span className="truncate">{rule.description || "—"}</span>
            <button className="icon-danger" disabled={busy} onClick={()=>removePublished(rule.id)} title="Delete rule"><Trash2 size={15}/></button>
          </div>
        )}
        {!status?.config.publishedPortRules?.length && <div className="muted published-empty">No published-port firewall rules configured</div>}
      </div>
    </div>

    <div className="panel">
      <div className="firewall-titlebar">
        <PanelTitle title="Create policy" subtitle="Rules are saved as draft; use Apply changes in the Firewall Engine panel"/>
      </div>

      <div className="rule-builder">
        <label><span>Source network</span><select value={source} onChange={e=>setSource(e.target.value)}>
          <option value="">Select network</option>{networks.map(n=><option key={n.id} value={n.id}>{n.name} · {n.subnets.join(", ")}</option>)}
        </select></label>
        <label><span>Destination network</span><select value={destination} onChange={e=>setDestination(e.target.value)}>
          <option value="">Select network</option>{networks.map(n=><option key={n.id} value={n.id}>{n.name} · {n.subnets.join(", ")}</option>)}
        </select></label>
        <label><span>Protocol</span><select value={protocol} onChange={e=>setProtocol(e.target.value as any)}>
          <option value="all">ANY</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option>
        </select></label>
        <label><span>Destination port</span><input disabled={!["tcp","udp"].includes(protocol)} value={port}
          onChange={e=>setPort(e.target.value.replace(/\D/g,""))} placeholder={["tcp","udp"].includes(protocol)?"1-65535":"—"}/></label>
        <label><span>Action</span><select value={action} onChange={e=>setAction(e.target.value as any)}>
          <option value="ACCEPT">ACCEPT</option><option value="DROP">DROP</option><option value="REJECT">REJECT</option>
        </select></label>
        <label className="description-field"><span>Description</span><input value={description} onChange={e=>setDescription(e.target.value)} placeholder="Optional"/></label>
        <button className="btn add-rule" disabled={busy} onClick={addRule}>Add rule</button>
      </div>
    </div>

    <div className="table-panel">
      <div className="fw-table-head"><span>Source</span><span>Destination</span><span>Protocol</span><span>Port</span><span>Action</span><span>Description</span><span></span></div>
      {(status?.config.rules ?? []).map(rule=><div className="fw-table-row" key={rule.id}>
        <div><strong>{byId.get(rule.sourceNetworkId)?.name ?? "Missing network"}</strong><small>{byId.get(rule.sourceNetworkId)?.subnets.join(", ")}</small></div>
        <div><strong>{byId.get(rule.destinationNetworkId)?.name ?? "Missing network"}</strong><small>{byId.get(rule.destinationNetworkId)?.subnets.join(", ")}</small></div>
        <code>{rule.protocol.toUpperCase()}</code><code>{rule.destinationPort ?? "ANY"}</code>
        <span className={rule.action==="ACCEPT"?"pill green":rule.action==="DROP"?"pill danger":"pill"}>{rule.action}</span>
        <span className="truncate">{rule.description || "—"}</span>
        <button className="icon-danger" disabled={busy} onClick={()=>remove(rule.id)} title="Delete rule"><Trash2 size={15}/></button>
      </div>)}
      {!status?.config.rules.length && <Empty text="No firewall rules configured"/>}
    </div>

    <div className="panel runtime-panel">
      <PanelTitle title="Runtime rules" subtitle="Rules currently installed in DRM-FIREWALL on the Docker host"/>
      <pre>{status?.runtime.installedRules.length ? status.runtime.installedRules.join("\n") : "No DRM runtime rules installed."}</pre>
    </div>
  </div>;
}



function RoutingPage(){
  const [status,setStatus]=useState<RoutingStatus|null>(null);const [error,setError]=useState('');const [destination,setDestination]=useState('');const [gateway,setGateway]=useState('');const [dev,setDev]=useState('');const [metric,setMetric]=useState('100');
  async function load(){try{setStatus(await getRoutingStatus());setError('')}catch(e){setError(e instanceof Error?e.message:String(e))}}
  useEffect(()=>{load();const t=window.setInterval(load,5000);return()=>window.clearInterval(t)},[]);
  async function add(){try{await createRoute({destination,gateway:gateway||null,dev:dev||null,metric:metric?Number(metric):null});setDestination('');setGateway('');await load()}catch(e){setError(e instanceof Error?e.message:String(e))}}
  return <div className="firewall-stack">
    {error&&<div className="error-banner"><Route size={18}/><div><strong>Routing error</strong><span>{error}</span></div></div>}
    <div className="panel routing-status"><div><PanelTitle title="IPv4 forwarding" subtitle="Linux host forwarding between VPN, Docker, VLAN and LAN"/></div><button className={status?.ipForward?'engine-toggle on':'engine-toggle'} onClick={async()=>{await setRoutingForward(!status?.ipForward);await load()}}><span className="toggle-knob"/><span className="toggle-label">{status?.ipForward?'ON':'OFF'}</span></button></div>
    <div className="panel"><PanelTitle title="Add static route" subtitle="ip route replace on the Docker host"/><div className="route-builder"><label><span>Destination</span><input value={destination} onChange={e=>setDestination(e.target.value)} placeholder="10.50.0.0/16"/></label><label><span>Gateway</span><input value={gateway} onChange={e=>setGateway(e.target.value)} placeholder="192.168.150.1"/></label><label><span>Interface</span><input value={dev} onChange={e=>setDev(e.target.value)} placeholder="wg0 / ens18"/></label><label><span>Metric</span><input value={metric} onChange={e=>setMetric(e.target.value.replace(/\D/g,''))}/></label><button className="btn primary" onClick={add}>Add route</button></div></div>
    <div className="table-panel"><div className="route-table-head"><span>Destination</span><span>Gateway</span><span>Interface</span><span>Protocol</span><span>Metric</span></div>{(status?.routes??[]).map((r:any,i)=><div className="route-table-row" key={i}><code>{r.dst||'default'}</code><code>{r.gateway||'direct'}</code><span>{r.dev||'—'}</span><span>{r.protocol||r.type||'kernel'}</span><span>{r.metric??'—'}</span></div>)}</div>
    <div className="panel"><PanelTitle title="DRM managed routes" subtitle="Persistent DRM routes re-applied when backend starts"/>{(status?.managedRoutes??[]).map(r=><div className="managed-route" key={r.id}><code>{r.destination}</code><span>via {r.gateway||'direct'} dev {r.dev||'auto'} metric {r.metric??'—'}</span><button className="icon-danger" onClick={async()=>{await removeRoute(r.id);await load()}}><Trash2 size={15}/></button></div>)}{!status?.managedRoutes.length&&<Empty text="No DRM managed routes"/>}</div>
  </div>
}

function WireGuardPage({topology}:{topology:Topology|null}){
  const [status,setStatus]=useState<WireGuardStatus|null>(null);
  const [error,setError]=useState('');
  const [name,setName]=useState('wg0');
  const [address,setAddress]=useState('10.8.0.1/24');
  const [listenPort,setListenPort]=useState('51820');
  const [selected,setSelected]=useState('');
  const [peerName,setPeerName]=useState('Laptop');
  const [clientAddress,setClientAddress]=useState('10.8.0.2/32');
  const [endpointHost,setEndpointHost]=useState(()=>window.location.hostname);
  const [endpointPort,setEndpointPort]=useState('');
  const [endpointHostTouched,setEndpointHostTouched]=useState(false);
  const [endpointPortTouched,setEndpointPortTouched]=useState(false);
  const [serverAllowed,setServerAllowed]=useState('10.8.0.2/32');
  const [clientAllowed,setClientAllowed]=useState('');
  const [dns,setDns]=useState('');
  const [keepalive,setKeepalive]=useState('25');
  const [config,setConfig]=useState('');
  const [configName,setConfigName]=useState('wireguard-client');
  const [qrSvg,setQrSvg]=useState('');

  async function load(){try{const x=await getWireGuard();setStatus(x);if(!selected&&x.interfaces?.[0])setSelected(x.interfaces[0].name);setError('')}catch(e){setError(e instanceof Error?e.message:String(e))}}
  useEffect(()=>{load();const t=window.setInterval(load,5000);return()=>window.clearInterval(t)},[]);
  const dockerRoutes=(topology?.networks??[]).flatMap(n=>n.subnets.map(s=>s.subnet).filter(Boolean) as string[]);
  const iface=status?.interfaces.find(i=>i.name===selected);

  useEffect(()=>{
    if(!endpointHostTouched) setEndpointHost(window.location.hostname);
    if(iface && !endpointPortTouched) setEndpointPort(String(iface.listenPort));
  },[iface?.name,iface?.listenPort,endpointHostTouched,endpointPortTouched]);

  async function createIface(){try{await createWgInterface({name,address,listenPort:Number(listenPort),mtu:1420});await load()}catch(e){setError(e instanceof Error?e.message:String(e))}}
  async function addPeer(){try{
    await createWgPeer(selected,{name:peerName,clientAddress,endpointHost:endpointHost.trim(),endpointPort:Number(endpointPort),serverAllowedIps:serverAllowed.split(',').map(x=>x.trim()).filter(Boolean),clientAllowedIps:clientAllowed.split(',').map(x=>x.trim()).filter(Boolean),dns:dns.trim()||undefined,persistentKeepalive:Number(keepalive||0)});
    setQrSvg('');setConfig('');await load();
  }catch(e){setError(e instanceof Error?e.message:String(e))}}

  async function openConfig(peer:{id:string;name:string}){
    try{setConfig(await getWgClientConfig(selected,peer.id));setConfigName(peer.name||'wireguard-client');setQrSvg('')}
    catch(e){setError(e instanceof Error?e.message:String(e))}
  }
  function downloadConfig(){
    if(!config)return;
    const blob=new Blob([config],{type:'text/plain;charset=utf-8'});
    const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`${configName.replace(/[^a-zA-Z0-9_.-]+/g,'-')}.conf`;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
  }
  async function showQr(peer:{id:string;name:string}){
    try{setConfig(await getWgClientConfig(selected,peer.id));setConfigName(peer.name||'wireguard-client');setQrSvg(await getWgClientQr(selected,peer.id))}
    catch(e){setError(e instanceof Error?e.message:String(e))}
  }

  return <div className="firewall-stack">
    {error&&<div className="error-banner"><KeyRound size={18}/><div><strong>WireGuard error</strong><span>{error}</span></div></div>}
    <div className="panel"><PanelTitle title="Create WireGuard interface" subtitle="Native Linux WireGuard in the host network namespace"/><div className="route-builder wg-interface-builder"><label><span>Name</span><input value={name} onChange={e=>setName(e.target.value)}/></label><label><span>Address</span><input value={address} onChange={e=>setAddress(e.target.value)}/></label><label><span>Listen port</span><input value={listenPort} onChange={e=>setListenPort(e.target.value.replace(/\D/g,''))}/></label><button className="btn primary" onClick={createIface}>Create interface</button></div></div>
    <div className="wg-layout"><div className="panel"><PanelTitle title="Interfaces" subtitle="Configured by DRM"/>{(status?.interfaces??[]).map(i=><button className={selected===i.name?'wg-interface-card active':'wg-interface-card'} key={i.name} onClick={()=>{setSelected(i.name);setEndpointPortTouched(false)}}><div><strong>{i.name}</strong><span>{i.address} · UDP {i.listenPort}</span></div><code>{i.peers.length} peers</code></button>)}{!status?.interfaces.length&&<Empty text="No WireGuard interfaces"/>}</div>
    <div className="panel"><PanelTitle title={iface?`${iface.name} peers`:'Peers'} subtitle={iface?`Public key: ${iface.publicKey}`:'Select an interface'}/>{iface&&<>
      <div className="wg-peer-builder wg-peer-builder-v2">
        <label><span>Name</span><input value={peerName} onChange={e=>setPeerName(e.target.value)}/></label>
        <label><span>Client address</span><input value={clientAddress} onChange={e=>setClientAddress(e.target.value)}/></label>
        <label><span>Endpoint address</span><input value={endpointHost} onChange={e=>{setEndpointHostTouched(true);setEndpointHost(e.target.value)}} placeholder="vpn.example.com"/></label>
        <label><span>Endpoint port</span><input value={endpointPort} onChange={e=>{setEndpointPortTouched(true);setEndpointPort(e.target.value.replace(/\D/g,''))}} placeholder={String(iface.listenPort)}/></label>
        <label><span>DNS</span><input value={dns} onChange={e=>setDns(e.target.value)} placeholder="1.1.1.1, 8.8.8.8"/></label>
        <label><span>Server AllowedIPs</span><input value={serverAllowed} onChange={e=>setServerAllowed(e.target.value)}/></label>
        <label><span>Client routes</span><input value={clientAllowed} onChange={e=>setClientAllowed(e.target.value)} placeholder="172.20.0.0/16, 192.168.150.0/24"/></label>
        <label><span>Keepalive</span><input value={keepalive} onChange={e=>setKeepalive(e.target.value.replace(/\D/g,''))}/></label>
        <button className="btn primary" onClick={addPeer}>Add peer</button>
      </div>
      <div className="wg-presets"><span>Client route presets:</span><button onClick={()=>setClientAllowed(dockerRoutes.join(', '))}>Docker networks</button><button onClick={()=>setClientAllowed('0.0.0.0/0')}>Full tunnel</button><button onClick={()=>setClientAllowed('')}>Clear</button></div>
      {iface.peers.map(peer=><div className="wg-peer-row" key={peer.id}><div><strong>{peer.name}</strong><span>{peer.clientAddress||'—'} · {peer.endpointHost||peer.endpoint||'no endpoint'}{peer.endpointPort?`:${peer.endpointPort}`:''} · server AllowedIPs {peer.serverAllowedIps.join(', ')}</span>{peer.dns&&<small>DNS: {peer.dns}</small>}</div><div className="wg-peer-actions"><button className="btn secondary" onClick={()=>openConfig(peer)}>Client config</button><button className="btn secondary" onClick={()=>showQr(peer)}><QrCode size={14}/> QR</button><button className="icon-danger" onClick={async()=>{await removeWgPeer(iface.name,peer.id);await load()}}><Trash2 size={15}/></button></div></div>)}</>}</div></div>
    {config&&<div className="panel"><PanelTitle title="Generated client configuration" subtitle="Private key is sensitive; download and QR are available only to Operator/Administrator"/><pre className="wg-config">{config}</pre><div className="wg-config-actions"><button className="btn secondary" onClick={()=>navigator.clipboard.writeText(config)}>Copy config</button><button className="btn primary" onClick={downloadConfig}><Download size={14}/> Download .conf</button>{qrSvg&&<button className="btn secondary" onClick={()=>setQrSvg('')}>Hide QR</button>}</div>{qrSvg&&<div className="wg-qr"><div dangerouslySetInnerHTML={{__html:qrSvg}}/><span>Scan with the WireGuard mobile app</span></div>}</div>}
  </div>
}

const topologyStorageKey="drm-topology-positions-v1";
function loadTopologyPositions():Record<string,{x:number;y:number}>{try{return JSON.parse(localStorage.getItem(topologyStorageKey)||"{}");}catch{return {};}}
function saveTopologyPosition(id:string,position:{x:number;y:number}){const p=loadTopologyPositions();p[id]=position;localStorage.setItem(topologyStorageKey,JSON.stringify(p));}

function TopologyView({data,firewall}:{data:Topology|null;firewall:FirewallStatus|null}) {
  const built=useMemo(()=>buildFlow(data,firewall),[data,firewall]);
  const [nodes,setNodes,onNodesChange]=useNodesState(built.nodes);
  useEffect(()=>{const current=new Map(nodes.map(n=>[n.id,n]));setNodes(built.nodes.map(n=>current.get(n.id)?{...n,position:current.get(n.id)!.position}:n));},[built.nodes]);
  const edges=built.edges;

  return <div className="topology-shell">
    <div className="topology-toolbar">
      <div>
        <strong>Live network topology</strong>
        <span>Docker networks, containers, published ports and firewall paths</span>
      </div>
      <div className="legend topology-legend">
        <span><i className="legend-network"/> Network</span>
        <span><i className="legend-container"/> Container</span>
        <span><i className="legend-port"/> Published port</span>
        <span><i className="legend-allow"/> Allowed path</span>
        <span><i className="legend-block"/> Blocked path</span>
      </div>
    </div>
    <div className="flow">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onNodeDragStop={(_e,node)=>saveTopologyPosition(node.id,node.position)}
        fitView
        minZoom={0.12}
        maxZoom={1.6}
        nodesDraggable={true}
        nodesConnectable={false}
        elementsSelectable={true}
        panOnDrag={[1,2]}
        selectionOnDrag={false}
        zoomOnDoubleClick={false}
      >
        <Background gap={22} size={1}/>
        <MiniMap zoomable pannable/>
        <Controls/>
      </ReactFlow>
    </div>
  </div>;
}

function buildFlow(data:Topology|null, firewall:FirewallStatus|null):{nodes:Node[];edges:Edge[]} {
  if(!data)return{nodes:[],edges:[]};

  const nodes:Node[]=[];
  const edges:Edge[]=[];
  const saved=loadTopologyPositions();
  const pos=(id:string,fallback:{x:number;y:number})=>saved[id] ?? fallback;
  const stableNetworks=[...data.networks].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id));
  const stableContainers=[...data.containers].sort((a,b)=>a.name.localeCompare(b.name)||a.id.localeCompare(b.id));

  const publishedRules=firewall?.config.publishedPortRules ?? [];

  // Internet node.
  nodes.push({
    id:"external-internet",
    position:pos("external-internet",{x:40,y:80}),
    draggable:false,
    selectable:true,
    data:{label:<div className="flow-node external-node">
      <div className="flow-node-icon external"><Wifi size={18}/></div>
      <div><strong>External / Internet</strong><span>Inbound traffic</span></div>
    </div>},
    style:{
      width:260,borderRadius:12,border:"1px solid #34445e",
      background:"#101724",color:"#e9f0fb",padding:4
    }
  });

  // Docker network nodes.
  stableNetworks.forEach((network,index)=>{
    const y=80+index*210;
    nodes.push({
      id:`net-${network.id}`,
      position:pos(`net-${network.id}`,{x:1320,y}),
      draggable:false,
      selectable:true,
      data:{label:<div className="flow-node">
        <div className="flow-node-icon network"><Network size={18}/></div>
        <div><strong>{network.name}</strong><span>{network.subnets[0]?.subnet || network.driver}</span></div>
      </div>},
      style:{
        width:270,borderRadius:12,border:"1px solid #26344c",
        background:"#111927",color:"#e9f0fb",padding:4
      }
    });
  });

  // Container nodes.
  stableContainers.forEach((container,index)=>{
    const y=50+index*150;
    nodes.push({
      id:`ctr-${container.id}`,
      position:pos(`ctr-${container.id}`,{x:880,y}),
      draggable:false,
      selectable:true,
      data:{label:<div className="flow-node">
        <div className="flow-node-icon container"><Container size={17}/></div>
        <div><strong>{container.name}</strong>
          <span>{container.networks.map(n=>n.ipv4Address).filter(Boolean).join(" · ") || "No IPv4"}</span>
          <small>{portSummary(container)}</small>
        </div>
      </div>},
      style:{
        width:310,borderRadius:12,border:"1px solid #243149",
        background:"#0d1420",color:"#e9f0fb",padding:4
      }
    });

    // Network attachment edges.
    container.networks.forEach(net=>{
      if(!net.networkId)return;
      edges.push({
        id:`attach-${net.networkId}-${container.id}`,
        source:`ctr-${container.id}`,
        target:`net-${net.networkId}`,
        animated:false,
        markerEnd:{type:MarkerType.ArrowClosed},
        style:{stroke:"#38577f",strokeWidth:1.5}
      });
    });
  });

  // Published port nodes and Internet -> port -> container paths.
  let publishedIndex=0;
  for(const container of stableContainers){
    for(const port of container.ports){
      for(const binding of port.published){
        const matching=publishedRules.filter(r=>r.enabled&&r.containerId===container.id&&r.protocol===port.protocol&&r.publishedPort===binding.hostPort&&r.containerPort===port.port&&(r.hostIp===binding.hostIp||(!r.hostIp&&!binding.hostIp)));
        const blocks=matching.filter(r=>r.action==="DROP"||r.action==="REJECT");
        const accepts=matching.filter(r=>r.action==="ACCEPT");
        const fullBlock=blocks.some(r=>r.sourceCidr==="0.0.0.0/0");
        const restricted=!fullBlock && (blocks.length>0 || (accepts.length>0 && !accepts.some(r=>r.sourceCidr==="0.0.0.0/0")));
        const isExplicitAccept=!fullBlock&&!restricted&&accepts.some(r=>r.sourceCidr==="0.0.0.0/0");
        const isBlocked=fullBlock;
        const color=isBlocked ? "#ff5b68" : restricted ? "#ffb84d" : isExplicitAccept ? "#32d296" : "#4d8dff";
        const stateLabel=isBlocked ? "BLOCKED" : restricted ? "RESTRICTED" : isExplicitAccept ? "ALLOW" : "OPEN";

        const portNodeId=`pub-${container.id}-${binding.hostIp}-${binding.hostPort}-${port.protocol}-${port.port}-${publishedIndex}`;
        const y=60+publishedIndex*115;

        nodes.push({
          id:portNodeId,
          position:pos(portNodeId,{x:460,y}),
          draggable:false,
          selectable:true,
          data:{label:<div className="flow-node port-node">
            <div className={isBlocked ? "flow-node-icon port blocked" : restricted ? "flow-node-icon port restricted" : "flow-node-icon port"}>
              <Plug size={17}/>
            </div>
            <div>
              <strong>{binding.hostIp || "0.0.0.0"}:{binding.hostPort}/{port.protocol}</strong>
              <span>→ {container.name}:{port.port}</span>
              <small className={isBlocked ? "blocked-text" : ""}>{stateLabel}</small>
            </div>
          </div>},
          style:{
            width:300,borderRadius:12,
            border:`1px solid ${isBlocked ? "#67313a" : restricted ? "#634d2d" : "#2a3d5a"}`,
            background:isBlocked ? "#1b1115" : restricted ? "#1c1810" : "#101825",
            color:"#e9f0fb",padding:4
          }
        });

        edges.push({
          id:`internet-${portNodeId}`,
          source:"external-internet",
          target:portNodeId,
          animated:!isBlocked && !restricted,
          markerEnd:{type:MarkerType.ArrowClosed,color},
          label:`${binding.hostIp || "0.0.0.0"}:${binding.hostPort}/${port.protocol}`,
          labelStyle:{fill:color,fontSize:9,fontWeight:700},
          labelBgStyle:{fill:"#0a1019",fillOpacity:.92},
          style:{stroke:color,strokeWidth:isBlocked?2.8:2,strokeDasharray:restricted?"7 4":undefined}
        });

        edges.push({
          id:`port-container-${portNodeId}`,
          source:portNodeId,
          target:`ctr-${container.id}`,
          animated:!isBlocked && !restricted,
          markerEnd:{type:MarkerType.ArrowClosed,color},
          label:`${port.port}/${port.protocol}`,
          labelStyle:{fill:color,fontSize:9,fontWeight:700},
          labelBgStyle:{fill:"#0a1019",fillOpacity:.92},
          style:{stroke:color,strokeWidth:isBlocked?2.8:2,strokeDasharray:restricted?"7 4":undefined}
        });

        publishedIndex+=1;
      }
    }
  }

  // Network-to-network firewall policy edges.
  const networkById=new Map(stableNetworks.map(n=>[n.id,n]));
  (firewall?.config.rules ?? []).filter(r=>r.enabled).forEach((rule,index)=>{
    if(!networkById.has(rule.sourceNetworkId) || !networkById.has(rule.destinationNetworkId))return;

    const isBlocked=rule.action==="DROP" || rule.action==="REJECT";
    const color=isBlocked ? "#ff5b68" : "#32d296";
    edges.push({
      id:`fw-net-${rule.id}`,
      source:`net-${rule.sourceNetworkId}`,
      target:`net-${rule.destinationNetworkId}`,
      animated:!isBlocked,
      markerEnd:{type:MarkerType.ArrowClosed,color},
      label:`${rule.protocol.toUpperCase()} ${rule.destinationPort ?? "ANY"} · ${rule.action}`,
      labelStyle:{fill:color,fontSize:9,fontWeight:700},
      labelBgStyle:{fill:"#0a1019",fillOpacity:.94},
      style:{stroke:color,strokeWidth:2.2,strokeDasharray:isBlocked?"6 4":undefined}
    });
  });

  return{nodes,edges};
}

function formatBytes(value:number){if(value<1024)return `${value.toFixed(0)} B`;if(value<1024*1024)return `${(value/1024).toFixed(1)} KB`;if(value<1024*1024*1024)return `${(value/(1024*1024)).toFixed(1)} MB`;return `${(value/(1024*1024*1024)).toFixed(2)} GB`;}
function formatRate(value:number){return `${formatBytes(value)}/s`;}

function portSummary(c:DockerContainer) {
  if(!c.ports.length)return "No exposed ports";
  return c.ports.slice(0,4).map(p=>{
    const pub=p.published[0];
    return pub ? `${pub.hostPort}→${p.containerPort}` : p.containerPort;
  }).join(" · ") + (c.ports.length>4 ? ` +${c.ports.length-4}` : "");
}
function formatHostIp(ip:string){ return !ip || ip==="0.0.0.0" ? "0.0.0.0" : ip==="::" ? "[::]" : ip; }
function NetworkRow({network}:{network:DockerNetwork}) { return <div className="network-row">
  <div className="network-symbol small"><Wifi size={16}/></div><div className="grow"><strong>{network.name}</strong><span>{network.driver} · {network.scope}</span></div>
  <div className="right-meta"><code>{network.subnets[0]?.subnet || "—"}</code><span>{network.containers.length} endpoints</span></div></div>; }
function PanelTitle({title,subtitle}:{title:string;subtitle:string}) { return <div className="panel-title"><div><h2>{title}</h2><span>{subtitle}</span></div></div>; }
function Metric({label,value}:{label:string;value:string}) { return <div className="metric"><span>{label}</span><strong>{value}</strong></div>; }
function Empty({text}:{text:string}) { return <div className="empty"><Server size={22}/><span>{text}</span></div>; }
export default AuthenticatedApp;
