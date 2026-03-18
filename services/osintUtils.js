const dns = require("dns").promises;
const net = require("net");
const axios = require("axios");

const TOP_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443];

function isIpAddress(value) {
  return net.isIP(value) !== 0;
}

function isDomain(value) {
  return /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value || "");
}

function normalizeDomain(domain) {
  return (domain || "").toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
}

function normalizeUrl(target) {
  if (!target) {
    return null;
  }
  const trimmed = target.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

async function safeAxiosGet(url, config = {}) {
  try {
    const response = await axios.get(url, {
      timeout: 8000,
      validateStatus: () => true,
      ...config,
    });
    return { ok: true, status: response.status, data: response.data, headers: response.headers };
  } catch (error) {
    const message = String(error.message || "");
    const status = Number.isInteger(error.response?.status) ? error.response.status : null;
    const sanitized = /ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNRESET|EACCES|ECONNABORTED|EHOSTUNREACH|ENETUNREACH|network/i.test(
      message
    )
      ? "Network request failed or was blocked for this provider."
      : message;
    return { ok: false, error: sanitized, status };
  }
}

function providerErrorLabel(response, fallback = "Provider unavailable.") {
  if (response?.error) {
    return response.error;
  }
  if (Number.isInteger(response?.status)) {
    return `HTTP ${response.status}`;
  }
  return fallback;
}

function stripDnsDot(value) {
  return String(value || "").replace(/\.$/, "");
}

function parseDohAnswers(recordType, answers = []) {
  if (!Array.isArray(answers)) {
    return [];
  }

  if (recordType === "A" || recordType === "AAAA") {
    return answers.map((answer) => String(answer.data || "").trim()).filter(Boolean);
  }
  if (recordType === "MX") {
    return answers
      .map((answer) => {
        const raw = String(answer.data || "").trim();
        const parts = raw.split(/\s+/);
        if (parts.length < 2) return null;
        return {
          priority: Number(parts[0]) || 0,
          exchange: stripDnsDot(parts.slice(1).join(" ")),
        };
      })
      .filter(Boolean);
  }
  if (recordType === "TXT") {
    return answers
      .map((answer) => String(answer.data || "").replace(/^"|"$/g, ""))
      .filter(Boolean)
      .map((txt) => [txt]);
  }
  if (recordType === "NS" || recordType === "CNAME") {
    return answers.map((answer) => stripDnsDot(answer.data)).filter(Boolean);
  }
  if (recordType === "SOA") {
    return answers.map((answer) => String(answer.data || "").trim()).filter(Boolean);
  }
  return answers.map((answer) => answer.data).filter(Boolean);
}

async function resolveDnsOverHttps(domain, recordType) {
  const clean = normalizeDomain(domain);
  const providers = [
    {
      name: "dns.google",
      url: `https://dns.google/resolve?name=${encodeURIComponent(clean)}&type=${encodeURIComponent(recordType)}`,
      parse: (data) => parseDohAnswers(recordType, data?.Answer || []),
    },
    {
      name: "cloudflare-dns",
      url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(clean)}&type=${encodeURIComponent(recordType)}`,
      config: { headers: { accept: "application/dns-json" } },
      parse: (data) => parseDohAnswers(recordType, data?.Answer || []),
    },
  ];

  for (const provider of providers) {
    const response = await safeAxiosGet(provider.url, provider.config || {});
    if (!response.ok || response.status >= 400 || !response.data) {
      continue;
    }

    const records = provider.parse(response.data);
    return {
      ok: true,
      provider: provider.name,
      records,
      empty: records.length === 0,
    };
  }

  return {
    ok: false,
    error: `No DoH records resolved for ${recordType}`,
  };
}

async function resolveDnsSnapshot(domain) {
  const clean = normalizeDomain(domain);
  const snapshot = { domain: clean, records: {}, errors: {} };
  const resolverDiagnostics = {};

  const tasks = [
    ["A", () => dns.resolve4(clean)],
    ["AAAA", () => dns.resolve6(clean)],
    ["MX", () => dns.resolveMx(clean)],
    ["TXT", () => dns.resolveTxt(clean)],
    ["NS", () => dns.resolveNs(clean)],
    ["CNAME", () => dns.resolveCname(clean)],
    ["SOA", () => dns.resolveSoa(clean)],
  ];

  await Promise.all(
    tasks.map(async ([name, handler]) => {
      try {
        const result = await handler();
        snapshot.records[name] = Array.isArray(result) ? result : [result];
      } catch (error) {
        const localError = error.code || error.message;
        const doh = await resolveDnsOverHttps(clean, name);
        if (doh.ok) {
          snapshot.records[name] = doh.records;
          resolverDiagnostics[name] = {
            resolvedVia: doh.provider,
            localResolver: localError,
            recordCount: Array.isArray(doh.records) ? doh.records.length : 0,
          };
        } else {
          snapshot.errors[name] = "DNS resolution unavailable from local and DoH resolvers.";
          resolverDiagnostics[name] = {
            localResolver: localError,
            dohResolver: doh.error || "DoH lookup failed",
          };
        }
      }
    })
  );

  if (Object.keys(snapshot.errors).length > 0 && Object.keys(resolverDiagnostics).length > 0) {
    snapshot.resolverDiagnostics = resolverDiagnostics;
  }

  return snapshot;
}

function scanPort(host, port, timeoutMs = 900) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = "closed";

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      status = "open";
      socket.destroy();
    });
    socket.once("timeout", () => {
      status = "filtered";
      socket.destroy();
    });
    socket.once("error", () => {
      status = "closed";
    });
    socket.once("close", () => {
      resolve({ port, status });
    });

    socket.connect(port, host);
  });
}

async function portScan(host, ports = TOP_PORTS) {
  const checks = await Promise.all(ports.map((port) => scanPort(host, port)));
  const openPorts = checks.filter((item) => item.status === "open").map((item) => item.port);
  return {
    host,
    openPorts,
    checks,
  };
}

async function getIpIntelligence(ip) {
  const providers = [
    {
      name: "ipwho.is",
      url: `https://ipwho.is/${encodeURIComponent(ip)}`,
      parse: (data) => {
        if (!data || data.success === false) return null;
        return {
          ip: data.ip,
          country: data.country,
          city: data.city,
          latitude: data.latitude,
          longitude: data.longitude,
          isp: data.connection?.isp || null,
          asn: data.connection?.asn || null,
          org: data.connection?.org || null,
        };
      },
    },
    {
      name: "ipapi.co",
      url: `https://ipapi.co/${encodeURIComponent(ip)}/json/`,
      parse: (data) => {
        if (!data || data.error) return null;
        return {
          ip: data.ip,
          country: data.country_name || data.country,
          city: data.city,
          latitude: data.latitude,
          longitude: data.longitude,
          isp: data.org || null,
          asn: data.asn || null,
          org: data.org || null,
        };
      },
    },
    {
      name: "ipinfo.io",
      url: `https://ipinfo.io/${encodeURIComponent(ip)}/json`,
      parse: (data) => {
        if (!data || data.bogon) return null;
        const [lat, lon] = String(data.loc || ",").split(",");
        return {
          ip: data.ip || ip,
          country: data.country || null,
          city: data.city || null,
          latitude: lat || null,
          longitude: lon || null,
          isp: data.org || null,
          asn: data.org || null,
          org: data.org || null,
        };
      },
    },
  ];

  for (const provider of providers) {
    const response = await safeAxiosGet(provider.url);
    if (!response.ok || !response.data || response.status >= 400) {
      continue;
    }
    const parsed = provider.parse(response.data);
    if (parsed) {
      return {
        ...parsed,
        success: true,
        source: provider.name,
      };
    }
  }

  return {
    ip,
    success: false,
    error: "All IP intelligence providers failed for this target.",
  };
}

async function enumerateSubdomainsFromCt(domain) {
  const clean = normalizeDomain(domain);
  const subdomainSet = new Set();
  const sourceStatus = [];

  const crt = await safeAxiosGet(`https://crt.sh/?q=%25.${clean}&output=json`, {
    headers: { "User-Agent": "osint-tool/1.0" },
  });
  if (crt.ok && crt.status < 400 && Array.isArray(crt.data)) {
    crt.data.forEach((row) => {
      const names = String(row.name_value || "")
        .split("\n")
        .map((name) => name.trim().toLowerCase());
      names.forEach((name) => {
        if (name.endsWith(clean)) {
          subdomainSet.add(name.replace(/^\*\./, ""));
        }
      });
    });
    sourceStatus.push({ source: "crt.sh", status: "ok", count: subdomainSet.size });
  } else {
    sourceStatus.push({
      source: "crt.sh",
      status: "failed",
      error: providerErrorLabel(crt, "crt.sh query unavailable."),
    });
  }

  const hackerTarget = await safeAxiosGet(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(clean)}`);
  if (hackerTarget.ok && hackerTarget.status < 400 && typeof hackerTarget.data === "string") {
    const before = subdomainSet.size;
    String(hackerTarget.data)
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .forEach((line) => {
        const [host] = line.split(",");
        const value = String(host || "").toLowerCase();
        if (value.endsWith(clean)) {
          subdomainSet.add(value);
        }
      });
    sourceStatus.push({ source: "hackertarget", status: "ok", count: subdomainSet.size - before });
  } else {
    sourceStatus.push({
      source: "hackertarget",
      status: "failed",
      error: providerErrorLabel(hackerTarget, "Hackertarget hostsearch unavailable."),
    });
  }

  const bufferOver = await safeAxiosGet(`https://dns.bufferover.run/dns?q=.${encodeURIComponent(clean)}`);
  if (bufferOver.ok && bufferOver.status < 400 && bufferOver.data) {
    const before = subdomainSet.size;
    const fdns = Array.isArray(bufferOver.data.FDNS_A) ? bufferOver.data.FDNS_A : [];
    fdns.forEach((line) => {
      const parts = String(line).split(",");
      const host = parts[1] ? parts[1].trim().toLowerCase() : "";
      if (host.endsWith(clean)) {
        subdomainSet.add(host);
      }
    });
    sourceStatus.push({ source: "bufferover", status: "ok", count: subdomainSet.size - before });
  } else {
    sourceStatus.push({
      source: "bufferover",
      status: "failed",
      error: providerErrorLabel(bufferOver, "BufferOver lookup unavailable."),
    });
  }

  return {
    source: "multi-source",
    domain: clean,
    subdomains: Array.from(subdomainSet).sort(),
    sources: sourceStatus,
    error: subdomainSet.size === 0 ? "No subdomains resolved from available sources." : null,
  };
}

async function reverseIpLookup(ip) {
  const response = await safeAxiosGet(`https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`);
  if (!response.ok || response.status >= 400) {
    return {
      ip,
      domains: [],
      error: providerErrorLabel(response, "Reverse IP provider unavailable."),
    };
  }

  const text = String(response.data || "");
  if (text.toLowerCase().includes("error")) {
    return { ip, domains: [], error: text };
  }

  const domains = text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  return { ip, domains };
}

function cloudFingerprintFromHost(hostname = "") {
  const value = hostname.toLowerCase();
  if (value.includes("amazonaws.com") || value.includes("cloudfront.net")) {
    return "AWS";
  }
  if (value.includes("azurewebsites.net") || value.includes("blob.core.windows.net")) {
    return "Azure";
  }
  if (value.includes("googleapis.com") || value.includes("googleusercontent.com")) {
    return "GCP";
  }
  if (value.includes("digitaloceanspaces.com")) {
    return "DigitalOcean";
  }
  return null;
}

async function detectCloudExposure(domain) {
  const clean = normalizeDomain(domain);
  const dnsSnapshot = await resolveDnsSnapshot(clean);
  const candidates = [
    ...(dnsSnapshot.records.CNAME || []),
    ...(dnsSnapshot.records.A || []),
    ...(dnsSnapshot.records.AAAA || []),
  ];

  const providers = new Set();
  candidates.forEach((entry) => {
    const provider = cloudFingerprintFromHost(String(entry));
    if (provider) {
      providers.add(provider);
    }
  });

  return {
    domain: clean,
    providers: Array.from(providers),
    dnsSnapshot,
  };
}

async function resolveDomainToIps(domain) {
  const clean = normalizeDomain(domain);
  try {
    const ipv4 = await dns.resolve4(clean);
    return { domain: clean, ips: ipv4 };
  } catch (error) {
    const doh = await resolveDnsOverHttps(clean, "A");
    if (doh.ok) {
      return {
        domain: clean,
        ips: doh.records,
        source: doh.provider,
        warning: `Local DNS resolver failed (${error.code || error.message}); used DoH fallback.`,
      };
    }
    return { domain: clean, ips: [] };
  }
}

function mapPortsToVulnIntel(openPorts) {
  const mapping = {
    22: [{ cve: "CVE-2024-6387", service: "OpenSSH", note: "Check version for regreSSHion exposure." }],
    80: [{ cve: "CVE-2021-41773", service: "Apache HTTPD", note: "Path traversal/RCE in vulnerable configs." }],
    443: [{ cve: "CVE-2023-44487", service: "HTTP/2", note: "Rapid Reset DoS risk in unpatched stacks." }],
    445: [{ cve: "CVE-2020-0796", service: "SMBv3", note: "SMBGhost vulnerability in old Windows builds." }],
    3306: [{ cve: "CVE-2012-2122", service: "MySQL", note: "Auth bypass in legacy MySQL versions." }],
    3389: [{ cve: "CVE-2019-0708", service: "RDP", note: "BlueKeep risk in unpatched legacy systems." }],
    5432: [{ cve: "CVE-2018-1058", service: "PostgreSQL", note: "search_path privilege escalation vector." }],
  };

  return openPorts.flatMap((port) => mapping[port] || []);
}

module.exports = {
  TOP_PORTS,
  isIpAddress,
  isDomain,
  normalizeDomain,
  normalizeUrl,
  safeAxiosGet,
  resolveDnsSnapshot,
  portScan,
  getIpIntelligence,
  enumerateSubdomainsFromCt,
  reverseIpLookup,
  detectCloudExposure,
  resolveDomainToIps,
  mapPortsToVulnIntel,
};
