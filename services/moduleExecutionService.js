const redTeamService = require("./redTeamService");
const blueTeamService = require("./blueTeamService");
const { countDashboardStats } = require("../db");

function plannedModuleResult(moduleKey, note, target, auxInput) {
  return {
    moduleKey,
    status: "partially_implemented",
    note,
    receivedInput: {
      target: target || null,
      auxInput: auxInput || null,
    },
  };
}

function buildRelationshipGraph(infraData, secondaryEntity) {
  const nodes = [];
  const edges = [];
  const domainNode = `domain:${infraData.domain}`;
  nodes.push({ id: domainNode, type: "domain", label: infraData.domain });

  (infraData.rootIps || []).forEach((ip) => {
    const id = `ip:${ip}`;
    nodes.push({ id, type: "ip", label: ip });
    edges.push({ from: domainNode, to: id, relation: "resolves_to" });
  });

  (infraData.subdomains?.subdomains || []).slice(0, 40).forEach((sub) => {
    const id = `subdomain:${sub}`;
    nodes.push({ id, type: "subdomain", label: sub });
    edges.push({ from: domainNode, to: id, relation: "contains_subdomain" });
  });

  if (secondaryEntity) {
    const id = `entity:${secondaryEntity}`;
    nodes.push({ id, type: "entity", label: secondaryEntity });
    edges.push({ from: domainNode, to: id, relation: "related_to" });
  }

  return { nodes, edges, totalNodes: nodes.length, totalEdges: edges.length };
}

async function executeRedModule(moduleKey, payload) {
  const target = String(payload.target || "").trim();
  const auxInput = String(payload.auxInput || "").trim();

  switch (moduleKey) {
    case "network_infrastructure_recon":
      return redTeamService.targetEnumeration(target);

    case "domain_dns_intelligence":
      return redTeamService.infrastructureMapping(target);

    case "web_application_recon":
      return redTeamService.targetEnumeration(target);

    case "identity_social_osint":
      return redTeamService.usernameIdentityIntel(target, auxInput);

    case "email_intelligence":
      return redTeamService.emailIntelligence(target, auxInput);

    case "credential_leak_intelligence":
      return redTeamService.dataLeakDetection(target);

    case "cloud_osint": {
      const infra = await redTeamService.infrastructureMapping(target);
      return {
        domain: infra.domain,
        cloudAssets: infra.cloudAssets,
        rootIps: infra.rootIps,
        subdomainCount: infra.subdomains?.subdomains?.length || 0,
      };
    }

    case "metadata_file_analysis":
      if (!payload.file) {
        return plannedModuleResult(
          moduleKey,
          "Upload an image/PDF/DOCX artifact to run metadata and hashing analysis.",
          target,
          auxInput
        );
      }
      return redTeamService.metadataExtraction(payload.file);

    case "relationship_graph_analysis": {
      const infra = await redTeamService.infrastructureMapping(target);
      return {
        domain: infra.domain,
        graph: buildRelationshipGraph(infra, auxInput),
        timeline: [
          { step: "Domain intel collected", at: new Date().toISOString() },
          { step: "Entities linked", at: new Date().toISOString() },
        ],
      };
    }

    case "automation_recon_pipelines":
      return redTeamService.reconPipeline(target);

    case "evasion_stealth":
      return plannedModuleResult(
        moduleKey,
        "Proxy rotation/TOR/stealth controls are cataloged and require external runtime connectors.",
        target,
        auxInput
      );

    case "offensive_intelligence_addons": {
      const pipeline = await redTeamService.reconPipeline(target);
      return {
        target: pipeline.domain,
        cveMapping: pipeline.vulnerabilityIntel,
        exploitDb: "Exploit DB linking is cataloged and requires external integration.",
        hostDetection: {
          hostsScanned: pipeline.stageSummary.hostsScanned,
          ipsDiscovered: pipeline.stageSummary.ipsDiscovered,
        },
      };
    }

    default:
      throw new Error("Unsupported red-team module key.");
  }
}

async function executeBlueModule(moduleKey, payload) {
  const target = String(payload.target || "").trim();
  const auxInput = String(payload.auxInput || "").trim();
  const user = payload.user;

  switch (moduleKey) {
    case "attack_surface_management":
      return blueTeamService.attackSurfaceMonitoring(target, user.id);

    case "threat_intelligence_ioc":
      return blueTeamService.threatIntelLookup(target);

    case "phishing_brand_protection":
      return blueTeamService.brandMonitoring(target, auxInput);

    case "data_leak_exposure_monitoring":
      return {
        credentialLeaks: await blueTeamService.credentialLeakMonitoring(target),
        leakIntel: plannedModuleResult(
          moduleKey,
          "GitHub/Paste/Tor public DB monitoring are represented in this module and can be extended by API connectors.",
          target,
          auxInput
        ),
      };

    case "employee_insider_risk_monitoring":
      return blueTeamService.credentialLeakMonitoring(target);

    case "security_analytics_dashboard": {
      const [stats, alerts] = await Promise.all([countDashboardStats(), blueTeamService.alertCenter()]);
      return {
        riskSummary: stats,
        openAlerts: alerts.totalOpen,
        alertSnapshot: alerts.alerts.slice(0, 20),
      };
    }

    case "log_enrichment_siem_integration":
      return {
        enrichment: await blueTeamService.logEnrichment(target),
        siemExport: plannedModuleResult(
          moduleKey,
          "Direct Splunk/ELK/QRadar export connectors are cataloged and can be enabled via integration adapters.",
          target,
          auxInput
        ),
      };

    case "vulnerability_intelligence":
      return blueTeamService.vulnerabilityIntelligence(target);

    case "continuous_monitoring_alerts": {
      let monitorResult = null;
      if (target) {
        monitorResult = await blueTeamService.attackSurfaceMonitoring(target, user.id);
      }
      const alerts = await blueTeamService.alertCenter();
      return {
        monitorResult,
        alerts,
        notifications: plannedModuleResult(
          moduleKey,
          "Email/Slack/Webhook notifications are cataloged and require notification channel configuration.",
          target,
          auxInput
        ),
      };
    }

    case "threat_hunting_support":
      return {
        huntResult: await blueTeamService.threatIntelLookup(target),
        historicalAnalysis: plannedModuleResult(
          moduleKey,
          "Historical behavior correlation is cataloged and can be extended with indexed data stores.",
          target,
          auxInput
        ),
      };

    case "correlation_engine": {
      const alerts = await blueTeamService.alertCenter();
      return {
        seed: target,
        incidentContext: auxInput || null,
        links: {
          alerts: alerts.alerts.slice(0, 30),
          totalOpenAlerts: alerts.totalOpen,
        },
      };
    }

    default:
      throw new Error("Unsupported blue-team module key.");
  }
}

module.exports = {
  executeRedModule,
  executeBlueModule,
};
