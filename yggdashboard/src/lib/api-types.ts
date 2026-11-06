/**
 * Types for this dashboard's own /api/* responses (src/routes/api/) -
 * distinct from src/lib/server/types.ts's raw Yggdrasil admin wire
 * types, which client code can never import (SvelteKit enforces that
 * boundary at build time). These are the hand-picked shapes the server
 * routes actually return.
 */

export interface StatusResponse {
  status: 'online' | 'degraded' | 'disconnected';
  uptime: number;
  buildName: string;
  buildVersion: string;
  garlicEnabled: boolean;
  peerCount: number;
  peersUp: number;
  polledAt: string;
}

export interface HistorySample {
  t: number;
  rxRate: number;
  txRate: number;
  garlicRelayedRate: number;
  garlicOriginatedRate: number;
}

export interface StatsResponse {
  rxRate: number;
  txRate: number;
  rxTotalPeerLink: number;
  txTotalPeerLink: number;
  rxTotalSessions: number;
  txTotalSessions: number;
  garlic: {
    enabled: boolean;
    originatedBytes: number;
    relayedBytes: number;
    originatedRate: number;
    relayedRate: number;
    transitPercent: number;
  };
  history: HistorySample[];
  polledAt: string;
}

export interface ApiPeer {
  key: string;
  remote: string | null;
  address: string | null;
  up: boolean;
  inbound: boolean;
  bytesRecvd: number;
  bytesSent: number;
  rateRecvd: number;
  rateSent: number;
  uptime: number;
  latencyNs: number | null;
  lastError: string | null;
  garlicCapable: boolean;
}

export interface PeersResponse {
  peers: ApiPeer[];
  polledAt: string;
}

export interface OriginatedCircuit {
  circuitId: string;
  hops: string[];
  closed: boolean;
  createdAt: string;
  expiresAt: string;
  packets: number;
  bytes: number;
}

export interface RelayedCircuit {
  circuitId: string;
  previousHop: string;
  nextHop: string;
  firstSeen: string;
  lastActive: string;
  packetsRelayed: number;
  bytesRelayed: number;
}

export interface CircuitsResponse {
  enabled: boolean;
  originated: OriginatedCircuit[];
  relayed: RelayedCircuit[];
  polledAt: string;
}

export interface GarlicSecurityCounters {
  replayDrops: number;
  malformedPackets: number;
  expiredPackets: number;
  authFailures: number;
  relayTableFull: number;
}

export interface GarlicAutoPoolEntry {
  circuitId: string;
  createdAt: string;
  hops: number;
}

export interface GarlicResponse {
  enabled: boolean;
  identity: { publicKey: string } | null;
  stats: {
    originatedCircuits: number;
    relayedCircuits: number;
    originatedPackets: number;
    originatedBytes: number;
    relayedPackets: number;
    relayedBytes: number;
    security: GarlicSecurityCounters;
  };
  knownPeers: Array<{ nodeKey: string; garlicPublicKey: string; lastSeen: string; selfVerified: boolean }>;
  autoPool: GarlicAutoPoolEntry[];
  network: {
    mode: string;
    guard: string | null;
    trusted: string[];
    relays: Array<{
      key: string;
      selfVerified: boolean;
      onionKeyExpires: string;
      failScore: number;
      successes: number;
      failures: number;
      rttMillis: number | null;
    }>;
  } | null;
  sites: Array<{
    name: string;
    domain: string;
    introPoints: number;
    published: boolean;
    lastPublished: string | null;
    error: string | null;
  }>;
  polledAt: string;
}

export interface GraphNode {
  key: string;
  address: string;
  isSelf: boolean;
}

export interface GraphEdge {
  from: string;
  to: string;
  type: 'yggdrasil' | 'garlic';
  circuitId?: string;
  active?: boolean;
}

export interface GraphResponse {
  nodes: GraphNode[];
  yggdrasilEdges: GraphEdge[];
  garlicEdges: GraphEdge[];
  polledAt: string;
}
