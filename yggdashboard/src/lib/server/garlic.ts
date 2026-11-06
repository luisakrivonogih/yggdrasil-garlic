import type { Snapshot } from './types';

export function computeGarlic(snap: Snapshot) {
  return {
    enabled: snap.garlic.enabled,
    identity: snap.garlic.identity ? { publicKey: snap.garlic.identity.publicKey } : null,
    stats: {
      originatedCircuits: snap.garlic.stats.originatedCircuits,
      relayedCircuits: snap.garlic.stats.relayedCircuits,
      originatedPackets: snap.garlic.stats.originatedPackets,
      originatedBytes: snap.garlic.stats.originatedBytes,
      relayedPackets: snap.garlic.stats.relayedPackets,
      relayedBytes: snap.garlic.stats.relayedBytes,
      security: {
        replayDrops: snap.garlic.stats.security.replayDrops,
        malformedPackets: snap.garlic.stats.security.malformedPackets,
        expiredPackets: snap.garlic.stats.security.expiredPackets,
        authFailures: snap.garlic.stats.security.authFailures,
        relayTableFull: snap.garlic.stats.security.relayTableFull
      }
    },
    knownPeers: snap.garlic.knownPeers.map((p) => ({
      nodeKey: p.nodeKey,
      garlicPublicKey: p.garlicPublicKey,
      lastSeen: p.lastSeen,
      selfVerified: p.selfVerified
    })),
    autoPool: snap.garlic.autoPool.map((c) => ({
      circuitId: c.circuitId,
      createdAt: c.createdAt,
      hops: c.hops
    })),
    network: snap.garlic.network
      ? {
          mode: snap.garlic.network.mode,
          guard: snap.garlic.network.guard ?? null,
          trusted: [...(snap.garlic.network.trusted ?? [])],
          relays: (snap.garlic.network.relays ?? []).map((r) => ({
            key: r.key,
            selfVerified: r.selfVerified,
            onionKeyExpires: r.onionKeyExpires,
            failScore: r.failScore ?? 0,
            successes: r.successes ?? 0,
            failures: r.failures ?? 0,
            rttMillis: r.rttMillis ?? null
          }))
        }
      : null,
    sites: (snap.garlic.sites ?? []).map((s) => ({
      name: s.name ?? '',
      domain: s.domain,
      introPoints: s.introPoints ?? 0,
      published: s.published,
      lastPublished: s.lastPublished ?? null,
      error: s.error ?? null
    })),
    polledAt: snap.polledAt
  };
}
