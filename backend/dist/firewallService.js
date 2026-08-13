import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { getTopology, listNetworks } from "./dockerService.js";
const execFileAsync = promisify(execFile);
const dataDir = process.env.DRM_DATA_DIR ?? "/data";
const configPath = `${dataDir}/firewall.json`;
const backupPath = `${dataDir}/firewall.backup.json`;
const appliedPath = `${dataDir}/firewall.applied.json`;
const chain = "DRM-FIREWALL";
const commentPrefix = "DRM:";
async function iptables(args) {
    return execFileAsync("iptables", ["-w", "5", ...args], {
        maxBuffer: 1024 * 1024
    });
}
async function chainExists() {
    try {
        await iptables(["-n", "-L", chain]);
        return true;
    }
    catch {
        return false;
    }
}
async function ensureChain() {
    if (!(await chainExists())) {
        await iptables(["-N", chain]);
    }
    // Ensure exactly one jump from DOCKER-USER and keep it first.
    try {
        await iptables(["-C", "DOCKER-USER", "-j", chain]);
    }
    catch {
        await iptables(["-I", "DOCKER-USER", "1", "-j", chain]);
    }
}
async function removeJump() {
    while (true) {
        try {
            await iptables(["-D", "DOCKER-USER", "-j", chain]);
        }
        catch {
            break;
        }
    }
}
export async function getFirewallConfig() {
    await mkdir(dataDir, { recursive: true });
    try {
        const parsed = JSON.parse(await readFile(configPath, "utf8"));
        return {
            ...parsed,
            rules: parsed.rules ?? [],
            publishedPortRules: parsed.publishedPortRules ?? []
        };
    }
    catch {
        return {
            enabled: false,
            rules: [],
            publishedPortRules: [],
            updatedAt: new Date().toISOString()
        };
    }
}
async function saveConfig(config) {
    await mkdir(dataDir, { recursive: true });
    await writeFile(configPath, JSON.stringify(config, null, 2));
}
async function saveBackup(config) {
    await mkdir(dataDir, { recursive: true });
    await writeFile(backupPath, JSON.stringify(config, null, 2));
}
async function getBackup() {
    try {
        const parsed = JSON.parse(await readFile(backupPath, "utf8"));
        return {
            ...parsed,
            rules: parsed.rules ?? [],
            publishedPortRules: parsed.publishedPortRules ?? []
        };
    }
    catch {
        return null;
    }
}
async function saveApplied(config) {
    await mkdir(dataDir, { recursive: true });
    await writeFile(appliedPath, JSON.stringify(config, null, 2));
}
async function getApplied() {
    try {
        const parsed = JSON.parse(await readFile(appliedPath, "utf8"));
        return {
            ...parsed,
            rules: parsed.rules ?? [],
            publishedPortRules: parsed.publishedPortRules ?? []
        };
    }
    catch {
        return {
            enabled: false,
            rules: [],
            publishedPortRules: [],
            updatedAt: new Date(0).toISOString()
        };
    }
}
function validateRule(rule) {
    if (!rule.sourceNetworkId || !rule.destinationNetworkId) {
        throw new Error("Source and destination networks are required");
    }
    if (rule.sourceNetworkId === rule.destinationNetworkId) {
        throw new Error("Source and destination networks must be different");
    }
    if (!["all", "tcp", "udp", "icmp"].includes(rule.protocol)) {
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
export async function addFirewallRule(input) {
    validateRule({ ...input, enabled: input.enabled ?? true });
    const config = await getFirewallConfig();
    const rule = {
        id: randomUUID(),
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
export async function deleteFirewallRule(id) {
    const config = await getFirewallConfig();
    const before = config.rules.length;
    config.rules = config.rules.filter((r) => r.id !== id);
    if (before === config.rules.length)
        throw new Error("Rule not found");
    config.updatedAt = new Date().toISOString();
    await saveConfig(config);
}
function validatePublishedPortRule(rule) {
    if (!rule.containerId || !rule.containerName)
        throw new Error("Container is required");
    if (!["tcp", "udp"].includes(rule.protocol))
        throw new Error("Published port protocol must be TCP or UDP");
    if (!Number.isInteger(rule.publishedPort) || rule.publishedPort < 1 || rule.publishedPort > 65535) {
        throw new Error("Published port must be 1..65535");
    }
    if (!Number.isInteger(rule.containerPort) || rule.containerPort < 1 || rule.containerPort > 65535) {
        throw new Error("Container port must be 1..65535");
    }
    if (!["ACCEPT", "DROP", "REJECT"].includes(rule.action))
        throw new Error("Unsupported action");
    if (!rule.sourceCidr || !/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(rule.sourceCidr)) {
        throw new Error("Source CIDR must be IPv4 CIDR, for example 0.0.0.0/0");
    }
}
export async function addPublishedPortRule(input) {
    const rule = {
        id: randomUUID(),
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
    const exists = container?.ports.some((p) => p.protocol === rule.protocol &&
        p.port === rule.containerPort &&
        p.published.some((b) => b.hostPort === rule.publishedPort && (b.hostIp || "0.0.0.0") === rule.hostIp));
    if (!exists)
        throw new Error("Selected Docker published port mapping no longer exists");
    const config = await getFirewallConfig();
    config.publishedPortRules.push(rule);
    config.updatedAt = new Date().toISOString();
    await saveConfig(config);
    return rule;
}
export async function deletePublishedPortRule(id) {
    const config = await getFirewallConfig();
    const before = config.publishedPortRules.length;
    config.publishedPortRules = config.publishedPortRules.filter((r) => r.id !== id);
    if (before === config.publishedPortRules.length)
        throw new Error("Published port rule not found");
    config.updatedAt = new Date().toISOString();
    await saveConfig(config);
}
function cidrV4(subnets) {
    return subnets
        .map((s) => s.subnet)
        .filter((x) => Boolean(x && x.includes(".")));
}
async function buildRuleCommands(config) {
    const networks = await listNetworks();
    const byId = new Map(networks.map((n) => [n.id, n]));
    const commands = [];
    // Always allow replies to connections initiated by an allowed direction.
    commands.push([
        "-A", chain,
        "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
        "-m", "comment", "--comment", `${commentPrefix}state`,
        "-j", "ACCEPT"
    ]);
    // Published host-port policy. DOCKER-USER sees packets after Docker DNAT,
    // so match the ORIGINAL destination port/address from conntrack.
    for (const rule of (config.publishedPortRules ?? []).filter((r) => r.enabled)) {
        validatePublishedPortRule(rule);
        const args = [
            "-A", chain,
            "-s", rule.sourceCidr,
            "-p", rule.protocol,
            "-m", "conntrack",
            "--ctstate", "NEW",
            "--ctorigdstport", String(rule.publishedPort)
        ];
        // For mappings bound to a concrete IPv4 host address, also match it.
        // 0.0.0.0 means all IPv4 host addresses, so no ctorigdst constraint is added.
        if (rule.hostIp && rule.hostIp !== "0.0.0.0" && rule.hostIp.includes(".")) {
            args.push("--ctorigdst", rule.hostIp);
        }
        args.push("-m", "comment", "--comment", `${commentPrefix}published:${rule.id}`, "-j", rule.action);
        commands.push(args);
    }
    for (const rule of config.rules.filter((r) => r.enabled)) {
        validateRule(rule);
        const src = byId.get(rule.sourceNetworkId);
        const dst = byId.get(rule.destinationNetworkId);
        if (!src || !dst) {
            throw new Error(`Network for rule ${rule.id} no longer exists`);
        }
        const srcCidrs = cidrV4(src.subnets);
        const dstCidrs = cidrV4(dst.subnets);
        if (!srcCidrs.length || !dstCidrs.length) {
            throw new Error(`Rule ${rule.id} requires IPv4 bridge subnets`);
        }
        for (const source of srcCidrs) {
            for (const destination of dstCidrs) {
                const args = ["-A", chain, "-s", source, "-d", destination];
                if (rule.protocol !== "all") {
                    args.push("-p", rule.protocol);
                }
                if (rule.destinationPort != null) {
                    args.push("--dport", String(rule.destinationPort));
                }
                if (rule.action === "ACCEPT") {
                    args.push("-m", "conntrack", "--ctstate", "NEW");
                }
                args.push("-m", "comment", "--comment", `${commentPrefix}${rule.id}`, "-j", rule.action);
                commands.push(args);
            }
        }
    }
    // Return control to Docker if no DRM policy matches.
    commands.push([
        "-A", chain,
        "-m", "comment", "--comment", `${commentPrefix}return`,
        "-j", "RETURN"
    ]);
    return commands;
}
async function render(config) {
    await ensureChain();
    await iptables(["-F", chain]);
    if (!config.enabled) {
        await removeJump();
        return;
    }
    // Re-add jump if removeJump was used during a prior disable.
    try {
        await iptables(["-C", "DOCKER-USER", "-j", chain]);
    }
    catch {
        await iptables(["-I", "DOCKER-USER", "1", "-j", chain]);
    }
    for (const args of await buildRuleCommands(config)) {
        await iptables(args);
    }
}
export async function applyFirewall() {
    const draft = await getFirewallConfig();
    const previousApplied = await getApplied();
    await saveBackup(previousApplied);
    const next = {
        ...draft,
        rules: draft.rules.map((r) => ({ ...r })),
        publishedPortRules: (draft.publishedPortRules ?? []).map((r) => ({ ...r })),
        enabled: true,
        updatedAt: new Date().toISOString()
    };
    try {
        await render(next);
        await saveApplied(next);
        await saveConfig(next);
        return getFirewallStatus();
    }
    catch (error) {
        try {
            await render(previousApplied);
            await saveApplied(previousApplied);
        }
        catch {
            // Preserve the original apply error.
        }
        throw error;
    }
}
export async function disableFirewall() {
    const draft = await getFirewallConfig();
    const previousApplied = await getApplied();
    await saveBackup(previousApplied);
    const next = {
        ...draft,
        rules: draft.rules.map((r) => ({ ...r })),
        publishedPortRules: (draft.publishedPortRules ?? []).map((r) => ({ ...r })),
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
    if (!backup)
        throw new Error("No rollback snapshot exists");
    const restored = {
        ...backup,
        rules: backup.rules.map((r) => ({ ...r })),
        publishedPortRules: (backup.publishedPortRules ?? []).map((r) => ({ ...r })),
        updatedAt: new Date().toISOString()
    };
    await render(restored);
    await saveApplied(restored);
    await saveConfig(restored);
    return getFirewallStatus();
}
export async function getFirewallStatus() {
    const config = await getFirewallConfig();
    const applied = await getApplied();
    const pendingChanges = JSON.stringify({
        enabled: config.enabled,
        rules: config.rules,
        publishedPortRules: config.publishedPortRules ?? []
    }) !==
        JSON.stringify({
            enabled: applied.enabled,
            rules: applied.rules,
            publishedPortRules: applied.publishedPortRules ?? []
        });
    let installedRules = [];
    let chainPresent = false;
    let jumpPresent = false;
    let error = null;
    try {
        chainPresent = await chainExists();
        if (chainPresent) {
            const { stdout } = await iptables(["-S", chain]);
            installedRules = stdout
                .split("\n")
                .map((x) => x.trim())
                .filter(Boolean);
        }
        try {
            await iptables(["-C", "DOCKER-USER", "-j", chain]);
            jumpPresent = true;
        }
        catch {
            jumpPresent = false;
        }
    }
    catch (e) {
        error = e instanceof Error ? e.message : String(e);
    }
    const [networks, topology] = await Promise.all([listNetworks(), getTopology()]);
    const networkRefs = networks
        .filter((n) => n.driver === "bridge")
        .map((n) => ({
        id: n.id,
        name: n.name,
        subnets: n.subnets.map((s) => s.subnet).filter((x) => Boolean(x))
    }))
        .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    const publishedPortRefs = topology.containers
        .flatMap((container) => container.ports.flatMap((port) => port.published
        .filter(() => port.protocol === "tcp" || port.protocol === "udp")
        .map((binding) => ({
        containerId: container.id,
        containerName: container.name,
        protocol: port.protocol,
        publishedPort: binding.hostPort,
        hostIp: binding.hostIp || "0.0.0.0",
        containerPort: port.port
    }))))
        .filter((port) => Number.isInteger(port.publishedPort) && port.publishedPort > 0)
        .sort((a, b) => a.containerName.localeCompare(b.containerName) ||
        a.publishedPort - b.publishedPort ||
        a.protocol.localeCompare(b.protocol) ||
        a.hostIp.localeCompare(b.hostIp));
    return {
        engine: "iptables",
        managedChain: chain,
        config,
        applied,
        pendingChanges,
        networkRefs,
        publishedPortRefs,
        runtime: {
            chainPresent,
            jumpPresent,
            installedRules,
            error
        }
    };
}
