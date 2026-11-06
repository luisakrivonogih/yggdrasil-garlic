/**
 * Wire types for Yggdrasil's admin socket responses. Field names and
 * optionality mirror the Go structs exactly - see:
 * - SelfInfo: src/admin/getself.go GetSelfResponse
 * - PeerEntry: src/admin/getpeers.go PeerEntry
 * - SessionEntry: src/admin/getsessions.go SessionEntry
 * - TreeEntry: src/admin/gettree.go TreeEntry
 * - PathEntry: src/admin/getpaths.go PathEntry
 * - Garlic*: src/garlic/admin.go's handlers - only registered at all
 *   when Garlic.Enabled is true, see the note above.
 */

export interface SelfInfo {
  build_name: string;
  build_version: string;
  key: string;
  address: string;
  subnet: string;
  routing_entries: number;
  /** Seconds since the node process started. */
  uptime: number;
}

export interface PeerEntry {
  remote?: string;
  up: boolean;
  inbound: boolean;
  address?: string;
  key: string;
  port: number;
  priority: number;
  cost: number;
  bytes_recvd?: number;
  bytes_sent?: number;
  rate_recvd?: number;
  rate_sent?: number;
  /** Seconds. */
  uptime?: number;
  /** Nanoseconds (Go time.Duration, plain number over JSON). */
  latency?: number;
  /** Nanoseconds elapsed since the last error - not a timestamp. */
  last_error_time?: number;
  last_error?: string;
}

export interface SessionEntry {
  address: string;
  key: string;
  bytes_recvd: number;
  bytes_sent: number;
  uptime: number;
}

export interface TreeEntry {
  address: string;
  key: string;
  parent: string;
  sequence: number;
}

export interface PathEntry {
  address: string;
  key: string;
  path: number[];
  sequence: number;
}

export interface GarlicCircuitOriginated {
  circuitId: string;
  hops: string[];
  closed: boolean;
  /** RFC3339. */
  createdAt: string;
  expiresAt: string;
  packets: number;
  bytes: number;
}

export interface GarlicCircuitRelayed {
  circuitId: string;
  previousHop: string;
  nextHop: string;
  firstSeen: string;
  lastActive: string;
  packetsRelayed: number;
  bytesRelayed: number;
}

export interface GarlicCircuits {
  originated: GarlicCircuitOriginated[];
  relayed: GarlicCircuitRelayed[];
}

export interface GarlicSecurityCounters {
  replayDrops: number;
  malformedPackets: number;
  expiredPackets: number;
  authFailures: number;
  relayTableFull: number;
}

export interface GarlicStats {
  originatedCircuits: number;
  relayedCircuits: number;
  originatedPackets: number;
  originatedBytes: number;
  relayedPackets: number;
  relayedBytes: number;
  security: GarlicSecurityCounters;
}

export interface GarlicIdentity {
  publicKey: string;
}

export interface GarlicKnownPeer {
  nodeKey: string;
  garlicPublicKey: string;
  lastSeen: string;
  selfVerified: boolean;
}

/** One relay from getGarlicPeers, with what this node learned about it. */
export interface GarlicRelay {
  key: string;
  selfVerified: boolean;
  onionKeyExpires: string;
  /** Decaying count of recent failures through this relay (0 = none). */
  failScore: number;
  successes: number;
  failures: number;
  /** Typical round trip of paths through this relay, if measured. */
  rttMillis?: number;
}

/** getGarlicPeers: trust and relay state. */
export interface GarlicNetwork {
  mode: string;
  trusted: string[];
  guard?: string;
  relays: GarlicRelay[];
}

/** One hosted site from getGarlicServices. */
export interface GarlicSite {
  name?: string;
  domain: string;
  introPoints: number;
  published: boolean;
  lastPublished?: string;
  error?: string;
}

export interface GarlicAutoPoolEntry {
  circuitId: string;
  /** RFC3339. */
  createdAt: string;
  hops: number;
}

/**
 * The dashboard's own view of Garlic: `enabled` is explicit (derived by
 * the poller from whether the getGarlic* admin calls succeed at all),
 * rather than inferred from all-zero fields - matches the top-level
 * status bar's "Garlic: Enabled/Disabled" requirement directly.
 */
export interface GarlicSnapshot {
  enabled: boolean;
  identity: GarlicIdentity | null;
  stats: GarlicStats;
  circuits: GarlicCircuits;
  knownPeers: GarlicKnownPeer[];
  autoPool: GarlicAutoPoolEntry[];
  network: GarlicNetwork | null;
  sites: GarlicSite[];
}

/** One historical sample of the live-updating metrics (Task 13). */
export interface HistorySample {
  /** Unix milliseconds. */
  t: number;
  rxRate: number;
  txRate: number;
  garlicRelayedRate: number;
  garlicOriginatedRate: number;
}

/** The combined, per-poll snapshot every /api/* route reads from. */
export interface Snapshot {
  self: SelfInfo;
  peers: PeerEntry[];
  sessions: SessionEntry[];
  tree: TreeEntry[];
  paths: PathEntry[];
  garlic: GarlicSnapshot;
  history: HistorySample[];
  polledAt: string;
  /** False until the very first successful poll completes. */
  ready: boolean;
  /** Whether the most recent poll tick could actually reach the admin socket at all (not falling back to stale/cached data). */
  adminReachable: boolean;
}

export const EMPTY_SELF: SelfInfo = {
  build_name: '',
  build_version: '',
  key: '',
  address: '',
  subnet: '',
  routing_entries: 0,
  uptime: 0
};

export const EMPTY_GARLIC_STATS: GarlicStats = {
  originatedCircuits: 0,
  relayedCircuits: 0,
  originatedPackets: 0,
  originatedBytes: 0,
  relayedPackets: 0,
  relayedBytes: 0,
  security: {
    replayDrops: 0,
    malformedPackets: 0,
    expiredPackets: 0,
    authFailures: 0,
    relayTableFull: 0
  }
};

export const EMPTY_GARLIC: GarlicSnapshot = {
  enabled: false,
  identity: null,
  stats: EMPTY_GARLIC_STATS,
  circuits: { originated: [], relayed: [] },
  knownPeers: [],
  autoPool: [],
  network: null,
  sites: []
};

export const EMPTY_SNAPSHOT: Snapshot = {
  self: EMPTY_SELF,
  peers: [],
  sessions: [],
  tree: [],
  paths: [],
  garlic: EMPTY_GARLIC,
  history: [],
  polledAt: '',
  ready: false,
  adminReachable: false
};
