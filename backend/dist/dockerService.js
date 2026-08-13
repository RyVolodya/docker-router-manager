import { dockerGet } from "./dockerClient.js";
export async function getDockerInfo() {
    return dockerGet("/info");
}
export async function listContainers() {
    return dockerGet("/containers/json?all=1");
}
export async function listNetworks() {
    const networks = await dockerGet("/networks");
    const inspected = await Promise.all(networks.map((n) => dockerGet(`/networks/${encodeURIComponent(n.Id)}`)));
    return inspected.map((network) => ({
        id: network.Id,
        name: network.Name,
        driver: network.Driver,
        scope: network.Scope,
        internal: network.Internal,
        attachable: network.Attachable,
        ingress: network.Ingress,
        ipv4Enabled: network.EnableIPv4 ?? true,
        ipv6Enabled: network.EnableIPv6 ?? false,
        subnets: (network.IPAM?.Config ?? []).map((config) => ({
            subnet: config.Subnet ?? null,
            gateway: config.Gateway ?? null,
            ipRange: config.IPRange ?? null
        })),
        containers: Object.entries(network.Containers ?? {}).map(([id, endpoint]) => ({
            id,
            name: endpoint.Name,
            endpointId: endpoint.EndpointID,
            macAddress: endpoint.MacAddress,
            ipv4Address: endpoint.IPv4Address,
            ipv6Address: endpoint.IPv6Address
        })),
        labels: network.Labels ?? {}
    }));
}
export async function getTopology() {
    const [networks, containers] = await Promise.all([listNetworks(), listContainers()]);
    const inspectedContainers = await Promise.all(containers.map((container) => dockerGet(`/containers/${encodeURIComponent(container.Id)}/json`)));
    const inspectById = new Map(inspectedContainers.map((container) => [container.Id, container]));
    return {
        generatedAt: new Date().toISOString(),
        networkCount: networks.length,
        containerCount: containers.length,
        runningContainerCount: containers.filter((c) => c.State === "running").length,
        networks,
        containers: containers.map((container) => {
            const inspected = inspectById.get(container.Id);
            const portMap = inspected?.NetworkSettings?.Ports ?? {};
            const exposedPorts = Object.keys(inspected?.Config?.ExposedPorts ?? {});
            const ports = Object.entries(portMap).map(([containerPort, bindings]) => ({
                containerPort,
                protocol: containerPort.split("/")[1] ?? "tcp",
                port: Number(containerPort.split("/")[0]),
                published: (bindings ?? []).map((binding) => ({
                    hostIp: binding.HostIp,
                    hostPort: Number(binding.HostPort)
                }))
            }));
            // Docker may expose a port without publishing it. Ensure those ports
            // still appear in the API and GUI.
            for (const exposed of exposedPorts) {
                if (!ports.some((port) => port.containerPort === exposed)) {
                    ports.push({
                        containerPort: exposed,
                        protocol: exposed.split("/")[1] ?? "tcp",
                        port: Number(exposed.split("/")[0]),
                        published: []
                    });
                }
            }
            ports.sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));
            return {
                id: container.Id,
                name: container.Names?.[0]?.replace(/^\//, "") ?? container.Id.slice(0, 12),
                image: container.Image,
                state: container.State,
                status: container.Status,
                ports,
                networks: Object.entries(container.NetworkSettings?.Networks ?? {}).map(([networkName, attachment]) => ({
                    networkName,
                    networkId: attachment.NetworkID ?? null,
                    ipv4Address: attachment.IPAddress ?? null,
                    ipv4PrefixLen: attachment.IPPrefixLen ?? null,
                    gateway: attachment.Gateway ?? null,
                    ipv6Address: attachment.GlobalIPv6Address ?? null,
                    macAddress: attachment.MacAddress ?? null
                }))
            };
        })
    };
}
