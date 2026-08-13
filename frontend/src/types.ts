export type NetworkEndpoint = {
  id: string;
  name: string;
  endpointId: string;
  macAddress: string;
  ipv4Address: string;
  ipv6Address: string;
};

export type DockerNetwork = {
  id: string;
  name: string;
  driver: string;
  scope: string;
  internal: boolean;
  attachable: boolean;
  ingress: boolean;
  ipv4Enabled: boolean;
  ipv6Enabled: boolean;
  subnets: Array<{ subnet: string | null; gateway: string | null; ipRange: string | null }>;
  containers: NetworkEndpoint[];
};

export type DockerContainer = {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
  ports: Array<{
    containerPort: string;
    protocol: string;
    port: number;
    published: Array<{
      hostIp: string;
      hostPort: number;
    }>;
  }>;
  networks: Array<{
    networkName: string;
    networkId: string | null;
    ipv4Address: string | null;
    ipv4PrefixLen: number | null;
    gateway: string | null;
    ipv6Address: string | null;
    macAddress: string | null;
  }>;
};

export type Topology = {
  generatedAt: string;
  networkCount: number;
  containerCount: number;
  runningContainerCount: number;
  networks: DockerNetwork[];
  containers: DockerContainer[];
};


export type FirewallRule = {
  id: string;
  sourceNetworkId: string;
  destinationNetworkId: string;
  protocol: "all" | "tcp" | "udp" | "icmp";
  destinationPort?: number | null;
  action: "ACCEPT" | "DROP" | "REJECT";
  enabled: boolean;
  description?: string;
};

export type FirewallStatus = {
  engine: string;
  managedChain: string;
  config: {
    enabled: boolean;
    rules: FirewallRule[];
    publishedPortRules: Array<{
      id: string;
      containerId: string;
      containerName: string;
      protocol: "tcp" | "udp";
      publishedPort: number;
      hostIp: string;
      containerPort: number;
      sourceCidr: string;
      action: "ACCEPT" | "DROP" | "REJECT";
      enabled: boolean;
      description?: string;
    }>;
    updatedAt: string;
  };
  applied: {
    enabled: boolean;
    rules: FirewallRule[];
    publishedPortRules: Array<{
      id: string;
      containerId: string;
      containerName: string;
      protocol: "tcp" | "udp";
      publishedPort: number;
      hostIp: string;
      containerPort: number;
      sourceCidr: string;
      action: "ACCEPT" | "DROP" | "REJECT";
      enabled: boolean;
      description?: string;
    }>;
    updatedAt: string;
  };
  pendingChanges: boolean;
  networkRefs: Array<{
    id: string;
    name: string;
    subnets: string[];
  }>;
  publishedPortRefs: Array<{
    containerId: string;
    containerName: string;
    protocol: "tcp" | "udp";
    publishedPort: number;
    hostIp: string;
    containerPort: number;
  }>;
  lastAppliedAt: string | null;
  terminateExistingPublishedConnections: boolean;
  runtime: {
    chainPresent: boolean;
    jumpPresent: boolean;
    installedRules: string[];
    error: string | null;
  };
};


export type NetworkStatsResponse = {
  generatedAt: string;
  containers: Array<{ id:string; name:string; readAt:string; rxBytes:number; txBytes:number; rxPackets:number; txPackets:number; networks:Array<{name:string;rxBytes:number;txBytes:number;rxPackets:number;txPackets:number}> }>;
};


export type RoutingStatus={ipForward:boolean;routes:any[];addresses:any[];links:any[];managedRoutes:Array<{id:string;destination:string;gateway?:string|null;dev?:string|null;metric?:number|null;enabled:boolean}>};
export type WireGuardStatus={interfaces:Array<{name:string;address:string;listenPort:number;mtu:number;publicKey:string;peers:Array<{id:string;name:string;publicKey:string;serverAllowedIps:string[];clientAllowedIps:string[];clientAddress?:string;endpoint?:string;endpointHost?:string;endpointPort?:number;dns?:string;persistentKeepalive:number}>}>;runtime:string[][]};
