// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import GarlicPanel from './GarlicPanel.svelte';
import type { GarlicResponse } from '$lib/api-types';

// Zeroed inline, not imported from $lib/server/* - component/client test
// files must never reach across that boundary, even though it would
// happen to type-check here (GarlicStats and GarlicResponse['stats']
// are structurally identical by design).
const EMPTY_STATS: GarlicResponse['stats'] = {
  originatedCircuits: 0,
  relayedCircuits: 0,
  originatedPackets: 0,
  originatedBytes: 0,
  relayedPackets: 0,
  relayedBytes: 0,
  security: { replayDrops: 0, malformedPackets: 0, expiredPackets: 0, authFailures: 0, relayTableFull: 0 }
};

describe('GarlicPanel render', () => {
  it('shows the disabled explanation and no identity/security sections when Garlic is off', () => {
    render(GarlicPanel, {
      props: { garlic: { enabled: false, identity: null, stats: EMPTY_STATS, knownPeers: [], autoPool: [], network: null, sites: [], polledAt: '' } }
    });
    expect(screen.getByText(/Garlic is disabled on this node/)).toBeInTheDocument();
    expect(screen.queryByText('Security')).not.toBeInTheDocument();
  });

  it('shows the auto-pool status panel and a self-verified/gossiped badge per known-peer row', () => {
    render(GarlicPanel, {
      props: {
        garlic: {
          enabled: true,
          identity: { publicKey: 'garlic-pub' },
          stats: EMPTY_STATS,
          knownPeers: [
            { nodeKey: 'peer-verified', garlicPublicKey: 'gpk1', lastSeen: '2026-08-10T00:00:00.000Z', selfVerified: true },
            { nodeKey: 'peer-gossiped', garlicPublicKey: 'gpk2', lastSeen: '2026-08-10T00:00:00.000Z', selfVerified: false }
          ],
          autoPool: [{ circuitId: 'circuit-1', createdAt: '2026-08-10T00:00:00.000Z', hops: 3 }],
          network: null,
          sites: [],
          polledAt: ''
        }
      }
    });

    expect(screen.getByText('Auto-built circuit pool (1)')).toBeInTheDocument();
    expect(screen.getByText('Self-verified')).toBeInTheDocument();
    expect(screen.getByText('Gossiped')).toBeInTheDocument();
  });

  it('shows hosted sites, the guard among the trusted peers and each relay state', () => {
    render(GarlicPanel, {
      props: {
        garlic: {
          enabled: true,
          identity: null,
          stats: EMPTY_STATS,
          knownPeers: [],
          autoPool: [],
          network: {
            mode: 'client',
            guard: 'trusted-a',
            trusted: ['trusted-a', 'trusted-b'],
            relays: [
              { key: 'relay-ok', selfVerified: true, onionKeyExpires: '', failScore: 0, successes: 4, failures: 0, rttMillis: 120 },
              { key: 'relay-bad', selfVerified: false, onionKeyExpires: '', failScore: 2.5, successes: 1, failures: 3, rttMillis: null },
              { key: 'relay-new', selfVerified: false, onionKeyExpires: '', failScore: 0, successes: 0, failures: 0, rttMillis: null }
            ]
          },
          sites: [
            { name: 'blog', domain: 'aaaa.domains.yggg', introPoints: 2, published: true, lastPublished: null, error: null },
            { name: '', domain: 'bbbb.domains.yggg', introPoints: 0, published: false, lastPublished: null, error: 'no usable relay known yet' }
          ],
          polledAt: ''
        }
      }
    });

    expect(screen.getByText('Hosted sites (2)')).toBeInTheDocument();
    expect(screen.getByText('blog')).toBeInTheDocument();
    expect(screen.getByText('(default)')).toBeInTheDocument();
    expect(screen.getByText('no usable relay known yet')).toBeInTheDocument();
    expect(screen.getByText('Guard')).toBeInTheDocument();
    expect(screen.getByText('Relays (3)')).toBeInTheDocument();
    expect(screen.getByText('ok')).toBeInTheDocument();
    expect(screen.getByText('failing')).toBeInTheDocument();
    expect(screen.getByText('unknown')).toBeInTheDocument();
    expect(screen.getByText('120 ms')).toBeInTheDocument();
  });
});
