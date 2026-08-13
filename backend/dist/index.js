import express from "express";
import { getDockerInfo, getTopology, listContainers, listNetworks } from "./dockerService.js";
import { addFirewallRule, addPublishedPortRule, applyFirewall, deleteFirewallRule, deletePublishedPortRule, disableFirewall, getFirewallStatus, rollbackFirewall } from "./firewallService.js";
const app = express();
const port = Number(process.env.PORT ?? 8080);
app.disable("x-powered-by");
app.use(express.json());
app.get("/health", (_req, res) => {
    res.json({ status: "ok", service: "docker-router-manager", version: "0.4.2" });
});
app.get("/api/docker/info", async (_req, res) => {
    try {
        const info = await getDockerInfo();
        res.json({
            name: info.Name,
            serverVersion: info.ServerVersion,
            containers: info.Containers,
            containersRunning: info.ContainersRunning,
            containersStopped: info.ContainersStopped,
            images: info.Images,
            driver: info.Driver,
            operatingSystem: info.OperatingSystem,
            architecture: info.Architecture,
            ncpu: info.NCPU,
            memTotal: info.MemTotal
        });
    }
    catch (error) {
        res.status(502).json({ error: "docker_api_error", message: error instanceof Error ? error.message : String(error) });
    }
});
app.get("/api/networks", async (_req, res) => {
    try {
        res.json(await listNetworks());
    }
    catch (error) {
        res.status(502).json({ error: "docker_api_error", message: error instanceof Error ? error.message : String(error) });
    }
});
app.get("/api/containers", async (_req, res) => {
    try {
        res.json(await listContainers());
    }
    catch (error) {
        res.status(502).json({ error: "docker_api_error", message: error instanceof Error ? error.message : String(error) });
    }
});
app.get("/api/topology", async (_req, res) => {
    try {
        res.json(await getTopology());
    }
    catch (error) {
        res.status(502).json({ error: "docker_api_error", message: error instanceof Error ? error.message : String(error) });
    }
});
app.get("/api/firewall/status", async (_req, res) => {
    try {
        res.json(await getFirewallStatus());
    }
    catch (error) {
        res.status(500).json({ error: "firewall_status_error", message: error instanceof Error ? error.message : String(error) });
    }
});
app.post("/api/firewall/rules", async (req, res) => {
    try {
        const rule = await addFirewallRule(req.body);
        res.status(201).json(rule);
    }
    catch (error) {
        res.status(400).json({ error: "invalid_firewall_rule", message: error instanceof Error ? error.message : String(error) });
    }
});
app.delete("/api/firewall/rules/:id", async (req, res) => {
    try {
        await deleteFirewallRule(req.params.id);
        res.status(204).end();
    }
    catch (error) {
        res.status(404).json({ error: "firewall_rule_not_found", message: error instanceof Error ? error.message : String(error) });
    }
});
app.post("/api/firewall/apply", async (_req, res) => {
    try {
        res.json(await applyFirewall());
    }
    catch (error) {
        res.status(500).json({ error: "firewall_apply_error", message: error instanceof Error ? error.message : String(error) });
    }
});
app.post("/api/firewall/disable", async (_req, res) => {
    try {
        res.json(await disableFirewall());
    }
    catch (error) {
        res.status(500).json({ error: "firewall_disable_error", message: error instanceof Error ? error.message : String(error) });
    }
});
app.post("/api/firewall/rollback", async (_req, res) => {
    try {
        res.json(await rollbackFirewall());
    }
    catch (error) {
        res.status(500).json({ error: "firewall_rollback_error", message: error instanceof Error ? error.message : String(error) });
    }
});
app.post("/api/firewall/published-port-rules", async (req, res) => {
    try {
        const rule = await addPublishedPortRule(req.body);
        res.status(201).json(rule);
    }
    catch (error) {
        res.status(400).json({ error: "invalid_published_port_rule", message: error instanceof Error ? error.message : String(error) });
    }
});
app.delete("/api/firewall/published-port-rules/:id", async (req, res) => {
    try {
        await deletePublishedPortRule(req.params.id);
        res.status(204).end();
    }
    catch (error) {
        res.status(404).json({ error: "published_port_rule_not_found", message: error instanceof Error ? error.message : String(error) });
    }
});
app.get("/api/published-ports", async (_req, res) => {
    try {
        const topology = await getTopology();
        const ports = topology.containers.flatMap((container) => container.ports.flatMap((port) => port.published.map((binding) => ({
            containerId: container.id,
            containerName: container.name,
            protocol: port.protocol,
            containerPort: port.port,
            hostIp: binding.hostIp || "0.0.0.0",
            hostPort: binding.hostPort
        }))));
        res.json(ports);
    }
    catch (error) {
        res.status(500).json({ error: "published_ports_error", message: error instanceof Error ? error.message : String(error) });
    }
});
app.listen(port, "0.0.0.0", () => console.log(`DRM backend listening on ${port}`));
