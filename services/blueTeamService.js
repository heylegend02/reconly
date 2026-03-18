const dns = require("dns").promises;
const axios = require("axios");
const {
  isIpAddress,
  isDomain,
  normalizeDomain,
  safeAxiosGet,
  resolveDnsSnapshot,
  enumerateSubdomainsFromCt,
  resolveDomainToIps,
  getIpIntelligence,
  portScan,
  TOP_PORTS,
  mapPortsToVulnIntel,
} = require("./osintUtils");
const {
  getMonitoredAsset,
  upsertMonitoredAsset,
  createAlert,
  listOpenAlerts,
  closeAlert,
} = require("../db");

function normalizeArray(values = []) {
  return Array.from(new Set(values.map((value) => String(value).toLowerCase()))).sort();
}

function diffArrays(before = [], after = []) {
  const beforeSet = new Set(before);
  const afterSet = new Set(after);
  const added = after.filter((item) => !beforeSet.has(item));
  const removed = before.filter((item) => !afterSet.has(item));
  return { added, removed };
}

async function collectAttackSurface(domainInput) {
  const domain = normalizeDomain(domainInput);
  const [dnsSnapshot, subdomains, rootIps] = await Promise.all([
    resolveDnsSnapshot(domain),
    enumerateSubdomainsFromCt(domain),
    resolveDomainToIps(domain),
  ]);

  return {
    domain,
    generatedAt: new Date().toISOString(),
    dns: {
      A: normalizeArray(dnsSnapshot.records.A || []),
      AAAA: normalizeArray(dnsSnapshot.records.AAAA || []),
      MX: normalizeArray((dnsSnapshot.records.MX || []).map((item) => item.exchange)),
      NS: normalizeArray(dnsSnapshot.records.NS || []),
      TXT: normalizeArray((dnsSnapshot.records.TXT || []).flat()),
      CNAME: normalizeArray(dnsSnapshot.records.CNAME || []),
    },
    subdomains: normalizeArray(subdomains.subdomains || []),
    ips: normalizeArray(rootIps.ips || []),
  };
}

async function attackSurfaceMonitoring(domainInput, userId) {
  const domain = normalizeDomain(domainInput);
  if (!isDomain(domain)) {
    throw new Error("Valid domain is required.");
  }

  const current = await collectAttackSurface(domain);
  const existing = await getMonitoredAsset(domain);
  let previous = null;
  if (existing) {
    try {
      previous = JSON.parse(existing.baseline_json);
    } catch {
      previous = null;
    }
  }

  const changes = previous
    ? {
        newSubdomains: diffArrays(previous.subdomains, current.subdomains),
        newIps: diffArrays(previous.ips, current.ips),
        dnsA: diffArrays(previous.dns.A || [], current.dns.A || []),
        dnsMX: diffArrays(previous.dns.MX || [], current.dns.MX || []),
        dnsNS: diffArrays(previous.dns.NS || [], current.dns.NS || []),
      }
    : null;

  await upsertMonitoredAsset(domain, JSON.stringify(current), userId);

  if (changes) {
    const issues = [];
    if (changes.newSubdomains.added.length > 0) {
      issues.push(`New subdomains: ${changes.newSubdomains.added.join(", ")}`);
    }
    if (changes.newIps.added.length > 0) {
      issues.push(`New IPs: ${changes.newIps.added.join(", ")}`);
    }
    if (changes.dnsA.added.length > 0 || changes.dnsMX.added.length > 0 || changes.dnsNS.added.length > 0) {
      issues.push("DNS record changes detected.");
    }

    for (const message of issues) {
      await createAlert({
        assetDomain: domain,
        alertType: "attack_surface_change",
        severity: "medium",
        message,
        source: "attack-surface-monitor",
        dataJson: changes,
      });
    }
  }

  return {
    domain,
    firstBaseline: !previous,
    currentSnapshot: current,
    previousSnapshot: previous,
    changes,
  };
}

async function virusTotalLookup(target) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { checked: false, reason: "VIRUSTOTAL_API_KEY not configured." };
  }

  const isIp = isIpAddress(target);
  const endpoint = isIp ? "ip_addresses" : "domains";
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(target)}`, {
      timeout: 8000,
      headers: { "x-apikey": apiKey },
    });
    return {
      checked: true,
      malicious: response.data?.data?.attributes?.last_analysis_stats?.malicious ?? null,
      suspicious: response.data?.data?.attributes?.last_analysis_stats?.suspicious ?? null,
      harmless: response.data?.data?.attributes?.last_analysis_stats?.harmless ?? null,
      reputation: response.data?.data?.attributes?.reputation ?? null,
    };
  } catch (error) {
    return {
      checked: false,
      reason: error.response?.status ? `VirusTotal HTTP ${error.response.status}` : error.message,
    };
  }
}

async function abuseIpLookup(ip) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return { checked: false, reason: "ABUSEIPDB_API_KEY not configured." };
  }
  try {
    const response = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      timeout: 8000,
      headers: {
        Key: apiKey,
        Accept: "application/json",
      },
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
      },
    });
    return {
      checked: true,
      abuseConfidenceScore: response.data?.data?.abuseConfidenceScore ?? null,
      countryCode: response.data?.data?.countryCode ?? null,
      totalReports: response.data?.data?.totalReports ?? 0,
      usageType: response.data?.data?.usageType ?? null,
    };
  } catch (error) {
    return {
      checked: false,
      reason: error.response?.status ? `AbuseIPDB HTTP ${error.response.status}` : error.message,
    };
  }
}

async function threatIntelLookup(targetInput) {
  const target = (targetInput || "").trim();
  if (!target) {
    throw new Error("Target IOC is required.");
  }

  const ipInfo = isIpAddress(target) ? await getIpIntelligence(target) : null;
  const [virusTotal, abuse] = await Promise.all([
    virusTotalLookup(target),
    isIpAddress(target) ? abuseIpLookup(target) : Promise.resolve({ checked: false, reason: "AbuseIPDB supports IP lookups only." }),
  ]);

  return {
    target,
    targetType: isIpAddress(target) ? "ip" : "domain_or_ioc",
    ipIntel: ipInfo,
    virusTotal,
    abuseIpdb: abuse,
  };
}

function generateTyposquats(brand, baseDomain) {
  const cleanBrand = (brand || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const root = normalizeDomain(baseDomain || "");
  const domainParts = root.split(".");
  const stem = domainParts.length > 1 ? domainParts[0] : cleanBrand;
  const tld = domainParts.length > 1 ? domainParts.slice(1).join(".") : "com";

  const candidates = new Set([
    `${cleanBrand}${tld === "com" ? "co" : "com"}.${tld}`,
    `${cleanBrand}-secure.${tld}`,
    `${cleanBrand}-login.${tld}`,
    `${stem}${stem.length > 2 ? stem.slice(1) : stem}.${tld}`,
    `${stem}${stem.length > 2 ? stem.slice(0, -1) : stem}.${tld}`,
    `${stem}support.${tld}`,
    `${stem}verify.${tld}`,
    `${stem}.net`,
    `${stem}.org`,
  ]);

  return Array.from(candidates).filter((value) => value.length > 3);
}

async function domainLiveCheck(domain) {
  try {
    const [ips, page] = await Promise.all([dns.resolve4(domain), safeAxiosGet(`https://${domain}`)]);
    return {
      domain,
      resolves: true,
      ips,
      httpStatus: page.status || null,
      title: page.ok ? String(page.data || "").slice(0, 120).replace(/\s+/g, " ").trim() : null,
    };
  } catch {
    return { domain, resolves: false, ips: [] };
  }
}

async function brandMonitoring(brand, primaryDomain) {
  if (!brand || brand.length < 2) {
    throw new Error("Brand name is required.");
  }

  const candidates = generateTyposquats(brand, primaryDomain || `${brand}.com`);
  const checks = [];
  for (const domain of candidates.slice(0, 20)) {
    checks.push(await domainLiveCheck(domain));
  }

  const active = checks.filter((item) => item.resolves);
  for (const hit of active) {
    await createAlert({
      assetDomain: hit.domain,
      alertType: "possible_typosquat",
      severity: "high",
      message: `Potential typosquatting domain detected: ${hit.domain}`,
      source: "brand-monitoring",
      dataJson: hit,
    });
  }

  const socialCandidates = [
    `https://github.com/${brand}`,
    `https://x.com/${brand}`,
    `https://www.instagram.com/${brand}/`,
  ];

  const socialChecks = await Promise.all(
    socialCandidates.map(async (url) => {
      const response = await safeAxiosGet(url, { maxRedirects: 2 });
      return {
        url,
        exists: response.ok && (response.status || 500) < 400,
        status: response.status || 0,
      };
    })
  );

  return {
    brand,
    primaryDomain,
    typosquatCandidates: candidates,
    activeCandidates: active,
    socialSignals: socialChecks,
  };
}

async function hibpLookup(email) {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) {
    return { checked: false, reason: "HIBP_API_KEY not configured", breaches: [] };
  }

  try {
    const response = await axios.get(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      {
        timeout: 8000,
        validateStatus: () => true,
        headers: {
          "hibp-api-key": apiKey,
          "user-agent": "osint-tool/1.0",
        },
      }
    );

    if (response.status === 404) {
      return { checked: true, breaches: [] };
    }
    if (response.status >= 400) {
      return { checked: false, reason: `HIBP HTTP ${response.status}`, breaches: [] };
    }
    return { checked: true, breaches: response.data || [] };
  } catch (error) {
    return { checked: false, reason: error.message, breaches: [] };
  }
}

async function credentialLeakMonitoring(emailsInput) {
  const emails = String(emailsInput || "")
    .split(/[,\n;]/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);

  if (emails.length === 0) {
    throw new Error("Provide at least one email.");
  }

  const results = [];
  for (const email of emails.slice(0, 30)) {
    const hibp = await hibpLookup(email);
    results.push({ email, hibp });
    if (hibp.checked && hibp.breaches.length > 0) {
      await createAlert({
        assetDomain: email.split("@")[1],
        alertType: "credential_exposure",
        severity: "high",
        message: `Credential exposure detected for ${email} (${hibp.breaches.length} breaches).`,
        source: "credential-monitoring",
        dataJson: hibp.breaches.map((b) => ({ Name: b.Name, BreachDate: b.BreachDate })),
      });
    }
  }

  return {
    totalChecked: results.length,
    exposures: results.filter((item) => item.hibp.breaches.length > 0).length,
    results,
  };
}

async function logEnrichment(logIpsInput) {
  const ips = String(logIpsInput || "")
    .split(/[,\n;]/)
    .map((item) => item.trim())
    .filter(Boolean);

  if (ips.length === 0) {
    throw new Error("Provide one or more IPs.");
  }

  const enriched = [];
  for (const ip of ips.slice(0, 50)) {
    const [geo, abuse] = await Promise.all([getIpIntelligence(ip), abuseIpLookup(ip)]);
    enriched.push({
      ip,
      geo,
      threatScore: abuse.checked ? abuse.abuseConfidenceScore : null,
      asn: geo?.asn || null,
      abuse,
    });
  }

  return {
    processed: enriched.length,
    enriched,
  };
}

async function alertCenter() {
  const open = await listOpenAlerts(500);
  return {
    totalOpen: open.length,
    alerts: open,
  };
}

async function acknowledgeAlert(alertId) {
  const id = Number(alertId);
  if (!id) {
    throw new Error("Invalid alert id.");
  }
  await closeAlert(id);
  return { closed: id };
}

async function vulnerabilityIntelligence(targetInput) {
  const target = (targetInput || "").trim();
  if (!target) {
    throw new Error("Target is required.");
  }

  let host = target;
  let resolution = null;
  if (isDomain(target)) {
    resolution = await resolveDomainToIps(target);
    if (resolution.ips.length === 0) {
      return {
        target,
        scannedHost: null,
        openPorts: [],
        cveIntel: [],
        rawChecks: [],
        status: "degraded",
        warning: "Domain could not be resolved to IP with available DNS resolvers.",
        resolution,
      };
    }
    host = resolution.ips[0];
  }

  let scan;
  try {
    scan = await portScan(host, TOP_PORTS);
  } catch (error) {
    return {
      target,
      scannedHost: host,
      openPorts: [],
      cveIntel: [],
      rawChecks: [],
      status: "degraded",
      warning: `Port scan failed: ${error.message}`,
      resolution,
    };
  }
  const cves = mapPortsToVulnIntel(scan.openPorts);

  if (cves.length > 0) {
    await createAlert({
      assetDomain: isDomain(target) ? normalizeDomain(target) : target,
      alertType: "vulnerability_exposure",
      severity: "medium",
      message: `Potential vulnerable services exposed on ${target}.`,
      source: "vulnerability-intel",
      dataJson: { openPorts: scan.openPorts, cves },
    });
  }

  return {
    target,
    scannedHost: host,
    openPorts: scan.openPorts,
    cveIntel: cves,
    rawChecks: scan.checks,
    resolution,
  };
}

module.exports = {
  attackSurfaceMonitoring,
  threatIntelLookup,
  brandMonitoring,
  credentialLeakMonitoring,
  logEnrichment,
  alertCenter,
  acknowledgeAlert,
  vulnerabilityIntelligence,
};
