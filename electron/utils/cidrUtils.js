'use strict';

/**
 * CIDR arithmetic utilities for IP-based split tunneling.
 *
 * Used by electron/vpn/index.js to compute the allowedIPs string passed to
 * WireGuard based on the user's split tunnel include/exclude IP list.
 *
 * Exclude mode: allowedIPs = full range MINUS the excluded CIDRs.
 *   → Excluded IPs route to physical adapter; everything else tunnels.
 *
 * Include mode: allowedIPs = only the user's listed CIDRs.
 *   → Listed IPs tunnel; everything else routes to physical adapter naturally.
 */

// ── IPv4 helpers ──────────────────────────────────────────────────────────────

/**
 * Convert a dotted-decimal IPv4 string to an unsigned integer.
 * Uses regular JS arithmetic (exact for integers up to 2^53).
 */
function ipv4ToInt(ip) {
  const p = ip.split('.');
  return ((parseInt(p[0], 10) * 256 + parseInt(p[1], 10)) * 256 + parseInt(p[2], 10)) * 256 + parseInt(p[3], 10);
}

/** Convert an unsigned 32-bit integer to dotted-decimal IPv4 string. */
function intToIpv4(n) {
  return [
    Math.floor(n / 16777216) & 0xff,
    Math.floor(n / 65536) & 0xff,
    Math.floor(n / 256) & 0xff,
    n & 0xff,
  ].join('.');
}

/**
 * Parse an IPv4 CIDR string into { start, end, prefixLen }.
 * start/end are inclusive unsigned integer bounds of the block.
 */
function parseCIDRv4(cidr) {
  const slash = cidr.lastIndexOf('/');
  const ip = cidr.slice(0, slash);
  const prefixLen = parseInt(cidr.slice(slash + 1), 10);
  const start = ipv4ToInt(ip);
  // /0 block covers the full 2^32 address space
  const blockSize = prefixLen === 0 ? 4294967296 : Math.pow(2, 32 - prefixLen);
  return { start, end: start + blockSize - 1, prefixLen };
}

/**
 * Convert a contiguous integer range [startInt, endInt] into the minimal set
 * of IPv4 CIDR blocks that exactly covers it.
 *
 * Algorithm: at each step find the largest aligned CIDR block starting at
 * `current` that fits within the remaining range, emit it, advance.
 */
function rangeToCIDRsV4(startInt, endInt) {
  const results = [];
  let current = startInt;

  while (current <= endInt) {
    // Count trailing zeros to determine max alignment (block size) at `current`.
    let trailingZeros = 0;
    if (current === 0) {
      trailingZeros = 32;
    } else {
      let tmp = current;
      while (tmp % 2 === 0) { tmp /= 2; trailingZeros++; }
    }

    // Find the smallest prefix length (largest block) that fits in [current, endInt].
    let prefixLen = 32 - trailingZeros;
    while (prefixLen <= 32) {
      const blockSize = prefixLen === 0 ? 4294967296 : Math.pow(2, 32 - prefixLen);
      if (current + blockSize - 1 <= endInt) break;
      prefixLen++;
    }

    const blockSize = prefixLen === 0 ? 4294967296 : Math.pow(2, 32 - prefixLen);
    results.push(`${intToIpv4(current)}/${prefixLen}`);

    current = current + blockSize;
    if (current > 4294967295) break; // exhausted IPv4 space
  }

  return results;
}

/**
 * Subtract subtractCidr from baseCidr.
 * Returns an array of CIDR strings covering all of baseCidr except subtractCidr.
 * If there is no overlap, returns [baseCidr] unchanged.
 */
function subtractCIDRv4(baseCidr, subtractCidr) {
  let base, sub;
  try {
    base = parseCIDRv4(baseCidr);
    sub = parseCIDRv4(subtractCidr);
  } catch (_) {
    return [baseCidr]; // malformed input — pass through
  }

  // No overlap: return base unchanged
  if (sub.end < base.start || sub.start > base.end) return [baseCidr];

  const result = [];
  // Addresses in base that come before the subtracted block
  if (sub.start > base.start) {
    result.push(...rangeToCIDRsV4(base.start, sub.start - 1));
  }
  // Addresses in base that come after the subtracted block
  if (sub.end < base.end) {
    result.push(...rangeToCIDRsV4(sub.end + 1, base.end));
  }
  return result;
}

// ── IPv6 helpers (BigInt) ──────────────────────────────────────────────────────

/** Expand a possibly-compressed IPv6 address to 8 full colon-separated groups. */
function ipv6Expand(ip) {
  if (ip.includes('::')) {
    const [left, right] = ip.split('::');
    const leftGroups = left ? left.split(':') : [];
    const rightGroups = right ? right.split(':') : [];
    const missing = 8 - leftGroups.length - rightGroups.length;
    const middle = Array(missing).fill('0');
    return [...leftGroups, ...middle, ...rightGroups];
  }
  return ip.split(':');
}

/** Convert an IPv6 address string to a 128-bit BigInt. */
function ipv6ToBigInt(ip) {
  const groups = ipv6Expand(ip);
  return groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g || '0', 16)), 0n);
}

/**
 * Convert a 128-bit BigInt to a full (uncompressed) IPv6 address string.
 * Produces the expanded form — valid input for WireGuard's AllowedIPs.
 */
function bigIntToIPv6(n) {
  const groups = [];
  let remaining = n;
  for (let i = 0; i < 8; i++) {
    groups.unshift((remaining & 0xffffn).toString(16).padStart(4, '0'));
    remaining >>= 16n;
  }
  return groups.join(':');
}

/** Parse an IPv6 CIDR string into { start, end, prefixLen } using BigInt. */
function parseCIDRv6(cidr) {
  const slash = cidr.lastIndexOf('/');
  const ip = cidr.slice(0, slash);
  const prefixLen = parseInt(cidr.slice(slash + 1), 10);
  const start = ipv6ToBigInt(ip);
  const blockSize = 1n << BigInt(128 - prefixLen);
  return { start, end: start + blockSize - 1n, prefixLen };
}

const MAX_IPV6 = (1n << 128n) - 1n;

/** Convert a contiguous BigInt range [startBig, endBig] to minimal IPv6 CIDRs. */
function rangeToCIDRsV6(startBig, endBig) {
  const results = [];
  let current = startBig;

  while (current <= endBig) {
    let trailingZeros = 0;
    if (current === 0n) {
      trailingZeros = 128;
    } else {
      let tmp = current;
      while ((tmp & 1n) === 0n) { tmp >>= 1n; trailingZeros++; }
    }

    let prefixLen = 128 - trailingZeros;
    while (prefixLen <= 128) {
      const blockSize = 1n << BigInt(128 - prefixLen);
      if (current + blockSize - 1n <= endBig) break;
      prefixLen++;
    }

    const blockSize = 1n << BigInt(128 - prefixLen);
    results.push(`${bigIntToIPv6(current)}/${prefixLen}`);

    current = current + blockSize;
    if (current > MAX_IPV6) break;
  }

  return results;
}

/** Subtract subtractCidr from baseCidr for IPv6. Returns array of IPv6 CIDRs. */
function subtractCIDRv6(baseCidr, subtractCidr) {
  let base, sub;
  try {
    base = parseCIDRv6(baseCidr);
    sub = parseCIDRv6(subtractCidr);
  } catch (_) {
    return [baseCidr];
  }

  if (sub.end < base.start || sub.start > base.end) return [baseCidr];

  const result = [];
  if (sub.start > base.start) {
    result.push(...rangeToCIDRsV6(base.start, sub.start - 1n));
  }
  if (sub.end < base.end) {
    result.push(...rangeToCIDRsV6(sub.end + 1n, base.end));
  }
  return result;
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Compute the allowedIPs string to pass to WireGuard based on the user's
 * split tunnel configuration.
 *
 * Include mode: only the user's listed CIDRs tunnel through VPN.
 * Exclude mode: everything EXCEPT the user's listed CIDRs tunnels.
 * Empty list (either mode): returns full default — no IP splitting applied.
 *
 * @param {object} splitTunnelingConfig  - { mode: 'include'|'exclude', ips: string[] }
 * @param {boolean} ipv6Enabled          - Whether IPv6 routes should be included
 * @returns {string}  Comma-separated allowedIPs string ready for WireGuard
 */
function buildAllowedIPs(splitTunnelingConfig, ipv6Enabled) {
  const { mode, ips } = splitTunnelingConfig;
  const fullDefault = ipv6Enabled ? '0.0.0.0/0, ::/0' : '0.0.0.0/0';

  if (!ips || ips.length === 0) return fullDefault;

  const ipv4IPs = ips.filter(ip => !ip.includes(':') && ip.includes('.'));
  const ipv6IPs = ips.filter(ip => ip.includes(':'));

  if (mode === 'include') {
    const included = [...ipv4IPs];
    if (ipv6Enabled) included.push(...ipv6IPs);
    return included.length > 0 ? included.join(', ') : fullDefault;
  }

  // Exclude mode: compute CIDR complement for IPv4
  let ipv4Set = ['0.0.0.0/0'];
  for (const exclude of ipv4IPs) {
    const next = [];
    for (const base of ipv4Set) {
      next.push(...subtractCIDRv4(base, exclude));
    }
    ipv4Set = next;
  }

  if (!ipv6Enabled) {
    return ipv4Set.join(', ');
  }

  // Exclude mode: compute CIDR complement for IPv6
  let ipv6Set = ['::/0'];
  for (const exclude of ipv6IPs) {
    const next = [];
    for (const base of ipv6Set) {
      next.push(...subtractCIDRv6(base, exclude));
    }
    ipv6Set = next;
  }

  return [...ipv4Set, ...ipv6Set].join(', ');
}

module.exports = {
  buildAllowedIPs,
  // Exported for unit testing
  subtractCIDRv4,
  subtractCIDRv6,
  rangeToCIDRsV4,
  rangeToCIDRsV6,
  ipv4ToInt,
  intToIpv4,
};
