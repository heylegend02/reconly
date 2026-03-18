const axios = require("axios");
const cheerio = require("cheerio");
const whois = require("whois-json");
const validator = require("validator");
const exifParser = require("exif-parser");
const pdfParse = require("pdf-parse");
const mammoth = require("mammoth");
const JSZip = require("jszip");
const net = require("net");
const {
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
} = require("./osintUtils");

const USERNAME_PLATFORMS = [
  { name: "GitHub", url: (u) => `https://github.com/${u}` },
  { name: "Reddit", url: (u) => `https://www.reddit.com/user/${u}` },
  { name: "Instagram", url: (u) => `https://www.instagram.com/${u}/` },
  { name: "X", url: (u) => `https://x.com/${u}` },
  { name: "Medium", url: (u) => `https://medium.com/@${u}` },
];

async function lookupWhois(domain) {
  try {
    return await whois(normalizeDomain(domain));
  } catch (error) {
    return { error: error.message };
  }
}

function parseTechStack(html, headers = {}) {
  const output = {
    cms: [],
    frameworks: [],
    server: headers.server || null,
    poweredBy: headers["x-powered-by"] || null,
  };

  const source = (html || "").toLowerCase();
  const $ = cheerio.load(html || "");

  if (source.includes("wp-content") || source.includes("wordpress")) {
    output.cms.push("WordPress");
  }
  if (source.includes("joomla")) {
    output.cms.push("Joomla");
  }
  if (source.includes("drupal")) {
    output.cms.push("Drupal");
  }

  const scripts = $("script")
    .map((_, el) => ($(el).attr("src") || "").toLowerCase())
    .get();

  const frameworkPatterns = [
    ["React", /react|_next\/static/],
    ["Vue", /vue/],
    ["Angular", /angular/],
    ["Svelte", /svelte/],
    ["jQuery", /jquery/],
  ];

  frameworkPatterns.forEach(([name, regex]) => {
    const found = scripts.some((src) => regex.test(src)) || regex.test(source);
    if (found) {
      output.frameworks.push(name);
    }
  });

  output.cms = Array.from(new Set(output.cms));
  output.frameworks = Array.from(new Set(output.frameworks));
  return output;
}

async function detectTechStack(urlOrDomain) {
  const url = normalizeUrl(urlOrDomain);
  const response = await safeAxiosGet(url, {
    headers: { "User-Agent": "osint-tool/1.0 (+red-team-tech-stack)" },
    maxRedirects: 5,
  });

  if (!response.ok || response.status >= 500) {
    return {
      url,
      error: response.error || `HTTP ${response.status}`,
      stack: null,
    };
  }

  return {
    url,
    status: response.status,
    title: cheerio.load(response.data || "")("title").text().trim() || null,
    stack: parseTechStack(String(response.data || ""), response.headers || {}),
  };
}

async function targetEnumeration(target) {
  const cleanTarget = (target || "").trim();
  if (!cleanTarget) {
    throw new Error("Target is required.");
  }

  if (isIpAddress(cleanTarget)) {
    const [ipIntel, scan] = await Promise.all([
      getIpIntelligence(cleanTarget),
      portScan(cleanTarget, TOP_PORTS),
    ]);

    return {
      targetType: "ip",
      target: cleanTarget,
      ipIntel,
      portScan: scan,
    };
  }

  if (isDomain(cleanTarget) || cleanTarget.includes(".")) {
    const domain = normalizeDomain(cleanTarget);
    const [whoisData, dnsSnapshot, subdomains, resolved, techStack] = await Promise.all([
      lookupWhois(domain),
      resolveDnsSnapshot(domain),
      enumerateSubdomainsFromCt(domain),
      resolveDomainToIps(domain),
      detectTechStack(domain),
    ]);

    let scan = null;
    if (resolved.ips.length > 0) {
      scan = await portScan(resolved.ips[0], TOP_PORTS);
    }

    return {
      targetType: "domain",
      target: domain,
      whois: whoisData,
      dns: dnsSnapshot,
      subdomains,
      resolvedIps: resolved.ips,
      techStack,
      portScan: scan,
    };
  }

  throw new Error("Unsupported target format. Use an IP or domain.");
}

async function checkUsernameProfile(url) {
  try {
    const response = await axios.get(url, {
      timeout: 7000,
      validateStatus: () => true,
      maxRedirects: 3,
      headers: { "User-Agent": "osint-tool/1.0 (+username-intel)" },
    });

    const exists = response.status < 400 && !String(response.data || "").toLowerCase().includes("not found");
    const title = cheerio.load(String(response.data || ""))("title").text().trim() || null;
    return { url, exists, status: response.status, title };
  } catch (error) {
    return { url, exists: false, status: 0, error: error.message };
  }
}

function correlateEmailToUsername(email, username) {
  if (!email || !username || !validator.isEmail(email)) {
    return { matched: false, confidence: "none", reason: "Missing/invalid input." };
  }

  const [local] = email.toLowerCase().split("@");
  const normalizedLocal = local.replace(/[^a-z0-9]/g, "");
  const normalizedUser = username.toLowerCase().replace(/[^a-z0-9]/g, "");

  if (normalizedLocal === normalizedUser) {
    return { matched: true, confidence: "high", reason: "Local part exactly matches username." };
  }
  if (normalizedLocal.includes(normalizedUser) || normalizedUser.includes(normalizedLocal)) {
    return { matched: true, confidence: "medium", reason: "Username appears within email local part." };
  }
  return { matched: false, confidence: "low", reason: "No direct correlation found." };
}

async function usernameIdentityIntel(username, email) {
  if (!username) {
    throw new Error("Username is required.");
  }

  const checks = await Promise.all(
    USERNAME_PLATFORMS.map(async (platform) => {
      const url = platform.url(username);
      const result = await checkUsernameProfile(url);
      return {
        platform: platform.name,
        ...result,
      };
    })
  );

  const found = checks.filter((item) => item.exists);

  return {
    username,
    emailCorrelation: correlateEmailToUsername(email, username),
    profiles: checks,
    discoveredCount: found.length,
  };
}

function smtpProbe(host, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;
    let banner = "";

    const finish = (result) => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve(result);
      }
    };

    socket.setTimeout(timeoutMs);
    socket.connect(25, host);

    socket.on("data", (data) => {
      banner += data.toString();
      finish({ reachable: true, banner: banner.trim().slice(0, 200) });
    });
    socket.on("timeout", () => finish({ reachable: false, reason: "timeout" }));
    socket.on("error", (error) => finish({ reachable: false, reason: error.message }));
    socket.on("close", () => {
      if (!resolved) {
        finish({ reachable: false, reason: "closed" });
      }
    });
  });
}

function parseEmailHeaders(rawHeaders) {
  const lines = String(rawHeaders || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const summary = {
    from: null,
    to: null,
    subject: null,
    date: null,
    messageId: null,
    receivedPath: [],
    authResults: [],
    suspiciousSignals: [],
  };

  lines.forEach((line) => {
    const lower = line.toLowerCase();
    if (lower.startsWith("from:")) {
      summary.from = line.slice(5).trim();
    } else if (lower.startsWith("to:")) {
      summary.to = line.slice(3).trim();
    } else if (lower.startsWith("subject:")) {
      summary.subject = line.slice(8).trim();
    } else if (lower.startsWith("date:")) {
      summary.date = line.slice(5).trim();
    } else if (lower.startsWith("message-id:")) {
      summary.messageId = line.slice(11).trim();
    } else if (lower.startsWith("received:")) {
      summary.receivedPath.push(line.slice(9).trim());
    } else if (lower.startsWith("authentication-results:")) {
      summary.authResults.push(line.slice(23).trim());
    }

    if (lower.includes("spf=fail")) summary.suspiciousSignals.push("SPF failed");
    if (lower.includes("dkim=fail")) summary.suspiciousSignals.push("DKIM failed");
    if (lower.includes("dmarc=fail")) summary.suspiciousSignals.push("DMARC failed");
  });

  summary.suspiciousSignals = Array.from(new Set(summary.suspiciousSignals));
  return summary;
}

async function hibpLookup(email) {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) {
    return {
      checked: false,
      reason: "HIBP_API_KEY not configured.",
      breaches: [],
    };
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

function suggestEmailPatterns(domain) {
  return {
    domain,
    commonPatterns: [
      `first.last@${domain}`,
      `firstlast@${domain}`,
      `f.last@${domain}`,
      `firstl@${domain}`,
      `first@${domain}`,
    ],
  };
}

async function emailIntelligence(email, rawHeaders) {
  const cleanEmail = (email || "").trim().toLowerCase();
  const syntaxValid = validator.isEmail(cleanEmail);
  const domain = syntaxValid ? cleanEmail.split("@")[1] : null;

  let mxRecords = [];
  let smtpStatus = { reachable: false, reason: "Not attempted" };

  if (domain) {
    const dnsSnapshot = await resolveDnsSnapshot(domain);
    mxRecords = dnsSnapshot.records.MX || [];
    if (mxRecords.length > 0) {
      smtpStatus = await smtpProbe(mxRecords[0].exchange);
    }
  }

  const [hibp, parsedHeaders] = await Promise.all([
    syntaxValid ? hibpLookup(cleanEmail) : Promise.resolve({ checked: false, reason: "Invalid email syntax", breaches: [] }),
    Promise.resolve(rawHeaders ? parseEmailHeaders(rawHeaders) : null),
  ]);

  return {
    email: cleanEmail,
    syntaxValid,
    domain,
    mxRecords,
    smtpStatus,
    breachLookup: hibp,
    headerAnalysis: parsedHeaders,
    patternHints: domain ? suggestEmailPatterns(domain) : null,
  };
}

async function infrastructureMapping(domainInput) {
  const domain = normalizeDomain(domainInput);
  if (!isDomain(domain)) {
    throw new Error("Valid domain is required.");
  }

  const [subdomains, dnsSnapshot, resolvedIps, cloud] = await Promise.all([
    enumerateSubdomainsFromCt(domain),
    resolveDnsSnapshot(domain),
    resolveDomainToIps(domain),
    detectCloudExposure(domain),
  ]);

  const subdomainToIp = [];
  for (const sub of subdomains.subdomains.slice(0, 35)) {
    const result = await resolveDomainToIps(sub);
    subdomainToIp.push(result);
  }

  const reverse = [];
  for (const ip of resolvedIps.ips.slice(0, 3)) {
    reverse.push(await reverseIpLookup(ip, { targetDomain: domain, maxDomains: 60 }));
  }

  return {
    domain,
    dnsSnapshot,
    rootIps: resolvedIps.ips,
    subdomains,
    subdomainToIp,
    reverseIp: reverse,
    reverseIpSummary: reverse.map((item) => ({
      ip: item.ip,
      totalDiscovered: item.summary?.totalDiscovered || 0,
      relatedToTarget: item.summary?.relatedToTarget || 0,
      returned: item.summary?.returned || 0,
      scope: item.summary?.scope || "none",
      truncated: Boolean(item.summary?.truncated),
      likelySharedHosting: Boolean(item.summary?.likelySharedHosting),
      error: item.error || null,
    })),
    cloudAssets: cloud,
  };
}

async function githubLeakSearch(query) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    return {
      checked: false,
      reason: "GITHUB_TOKEN not configured for GitHub code search.",
      matches: [],
    };
  }

  try {
    const response = await axios.get("https://api.github.com/search/code", {
      timeout: 9000,
      params: { q: `${query} in:file` },
      headers: {
        authorization: `Bearer ${token}`,
        "user-agent": "osint-tool/1.0",
        accept: "application/vnd.github+json",
      },
    });

    const items = (response.data?.items || []).slice(0, 20).map((item) => ({
      name: item.name,
      path: item.path,
      repository: item.repository?.full_name,
      htmlUrl: item.html_url,
    }));

    return {
      checked: true,
      totalCount: response.data?.total_count || 0,
      matches: items,
    };
  } catch (error) {
    return {
      checked: false,
      reason: error.response?.status ? `GitHub HTTP ${error.response.status}` : error.message,
      matches: [],
    };
  }
}

async function pastebinSearch(query) {
  const response = await safeAxiosGet(`https://psbdmp.ws/api/v3/search/${encodeURIComponent(query)}`);
  if (!response.ok || response.status >= 400 || !Array.isArray(response.data)) {
    return {
      checked: false,
      reason: response.error || `HTTP ${response.status}`,
      matches: [],
    };
  }

  const matches = response.data.slice(0, 20).map((item) => ({
    id: item.id,
    time: item.time,
    tags: item.tags || [],
  }));

  return {
    checked: true,
    totalCount: response.data.length,
    matches,
  };
}

function collectOnionCandidatesFromText(text) {
  const matches = String(text || "").match(/[a-z2-7]{16,56}\.onion(?:\/[^\s"'<>]*)?/gi) || [];
  return Array.from(new Set(matches.map((item) => item.toLowerCase())));
}

async function darkWebMentionSearch(query) {
  const source = "ahmia.fi";
  const response = await safeAxiosGet(`https://ahmia.fi/search/?q=${encodeURIComponent(query)}`, {
    headers: { "User-Agent": "osint-tool/1.0 (+dark-web-mentions)" },
  });

  if (!response.ok || response.status >= 400) {
    return {
      checked: false,
      source,
      reason: response.error || `HTTP ${response.status}`,
      matches: [],
    };
  }

  const html = String(response.data || "");
  const $ = cheerio.load(html);
  const collected = [];

  // Ahmia pages can change structure; collect any onion-looking values from href/title/snippet context.
  $("a[href]").each((_, el) => {
    const href = String($(el).attr("href") || "").trim();
    const title = $(el).text().trim().replace(/\s+/g, " ");
    const snippet = $(el).closest("article, .result, .search-result, li, div").text().trim().slice(0, 260);
    const onionCandidates = collectOnionCandidatesFromText(`${href} ${title} ${snippet}`);

    onionCandidates.forEach((onion) => {
      const normalized = onion.startsWith("http") ? onion : `http://${onion}`;
      collected.push({
        onionUrl: normalized,
        title: title || null,
        snippet: snippet || null,
      });
    });
  });

  // Fallback regex scan over the full page body.
  collectOnionCandidatesFromText(html).forEach((onion) => {
    const normalized = onion.startsWith("http") ? onion : `http://${onion}`;
    collected.push({
      onionUrl: normalized,
      title: null,
      snippet: null,
    });
  });

  const deduped = [];
  const seen = new Set();
  collected.forEach((item) => {
    const key = item.onionUrl.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(item);
    }
  });

  return {
    checked: true,
    source,
    query,
    totalCount: deduped.length,
    matches: deduped.slice(0, 25),
    note: deduped.length === 0 ? "No indexed onion mentions found for this query." : null,
  };
}

async function dataLeakDetection(query) {
  if (!query || query.length < 3) {
    throw new Error("Provide at least 3 characters for leak hunting.");
  }

  const [github, pastebin, darkWeb] = await Promise.all([
    githubLeakSearch(query),
    pastebinSearch(query),
    darkWebMentionSearch(query),
  ]);

  return {
    query,
    github,
    pastebin,
    darkWeb,
  };
}

function parseImageMetadata(buffer) {
  const parser = exifParser.create(buffer);
  const result = parser.parse();
  return {
    tags: result.tags || {},
    imageSize: result.imageSize || null,
    hasGps: Boolean(result.tags?.GPSLatitude && result.tags?.GPSLongitude),
  };
}

async function parseDocxMetadata(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const coreFile = zip.file("docProps/core.xml");
  if (!coreFile) {
    return { metadata: {}, note: "No core metadata found." };
  }
  const coreXml = await coreFile.async("text");
  const textResult = await mammoth.extractRawText({ buffer });

  const extractTag = (tag) => {
    const regex = new RegExp(`<${tag}[^>]*>(.*?)<\\/${tag}>`, "i");
    const match = coreXml.match(regex);
    return match ? match[1] : null;
  };

  return {
    metadata: {
      creator: extractTag("dc:creator"),
      lastModifiedBy: extractTag("cp:lastModifiedBy"),
      created: extractTag("dcterms:created"),
      modified: extractTag("dcterms:modified"),
      title: extractTag("dc:title"),
      subject: extractTag("dc:subject"),
    },
    textPreview: textResult.value.slice(0, 800),
  };
}

async function metadataExtraction(file) {
  if (!file) {
    throw new Error("Please upload a file.");
  }

  const ext = (file.originalname.split(".").pop() || "").toLowerCase();
  const mime = file.mimetype || "";

  if (mime.startsWith("image/") || ["jpg", "jpeg", "png", "tiff", "webp"].includes(ext)) {
    return {
      fileName: file.originalname,
      type: "image",
      metadata: parseImageMetadata(file.buffer),
    };
  }

  if (mime.includes("pdf") || ext === "pdf") {
    const parsed = await pdfParse(file.buffer);
    return {
      fileName: file.originalname,
      type: "pdf",
      metadata: parsed.info || {},
      textSample: (parsed.text || "").slice(0, 1200),
      pages: parsed.numpages,
    };
  }

  if (
    mime.includes("wordprocessingml") ||
    ext === "docx"
  ) {
    const metadata = await parseDocxMetadata(file.buffer);
    return {
      fileName: file.originalname,
      type: "docx",
      ...metadata,
    };
  }

  throw new Error("Unsupported file type. Upload image, PDF, or DOCX.");
}

async function reconPipeline(domainInput) {
  const domain = normalizeDomain(domainInput);
  if (!isDomain(domain)) {
    throw new Error("Valid domain required for automated recon.");
  }

  const subdomainsResult = await enumerateSubdomainsFromCt(domain);
  const subdomains = subdomainsResult.subdomains.slice(0, 25);
  const ipMap = [];
  const allIps = new Set();

  for (const sub of [domain, ...subdomains]) {
    const resolved = await resolveDomainToIps(sub);
    ipMap.push(resolved);
    resolved.ips.forEach((ip) => allIps.add(ip));
  }

  const scanResults = [];
  for (const ip of Array.from(allIps).slice(0, 8)) {
    const scan = await portScan(ip, TOP_PORTS);
    scanResults.push(scan);
  }

  const vulnerabilities = scanResults.map((scan) => ({
    host: scan.host,
    openPorts: scan.openPorts,
    vulnerabilities: mapPortsToVulnIntel(scan.openPorts),
  }));

  return {
    domain,
    stageSummary: {
      subdomainsDiscovered: subdomainsResult.subdomains.length,
      ipsDiscovered: allIps.size,
      hostsScanned: scanResults.length,
    },
    subdomains: subdomainsResult,
    ipMap,
    scanResults,
    vulnerabilityIntel: vulnerabilities,
  };
}

module.exports = {
  targetEnumeration,
  usernameIdentityIntel,
  emailIntelligence,
  infrastructureMapping,
  dataLeakDetection,
  metadataExtraction,
  reconPipeline,
};
