/**
 * OpenAPI path and schemas of the certificate overview
 * (GET /api/v1/certificates/overview), spread into
 * app/api/v1/openapi.json/route.ts.
 */

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });

const RENEWAL_STATES = ["scheduled", "due", "overdue", "expired", "manual", "replace_soon", "pending", "missing", "unknown", "inactive"] as const;

export const CERTIFICATE_OVERVIEW_OPENAPI_PATHS = {
  "/api/v1/certificates/overview": {
    get: {
      tags: ["Certificates"],
      summary: "Certificate overview with expiry and renewal",
      description:
        "Requires certificates:read. Every certificate the caller may see as one list, as on the certificates page: the " +
        "certificates Caddy obtains with ACME for proxy hosts without a chosen certificate, imported certificates and " +
        "managed certificate entries. Each row says how the certificate is obtained, when it expires, where its renewal " +
        "stands and which proxy hosts and L4 hosts (with l4_proxy_hosts:read) terminate TLS with it. Imported " +
        "certificates are read from their PEM; for ACME certificates the product reads the certificate Caddy serves " +
        "for the domain with a TLS handshake over the internal network (cached for an hour), so their expiry is null " +
        "until Caddy has obtained one. A role scoped to tags sees the certificates of its in-scope proxy hosts. " +
        "No PEM or key material is returned.",
      operationId: "getCertificateOverview",
      responses: {
        "200": { description: "The overview", content: { "application/json": { schema: ref("CertificateOverview") } } },
        "401": { $ref: "#/components/responses/Unauthorized" },
        "403": { $ref: "#/components/responses/Forbidden" },
      },
    },
  },
};

export const CERTIFICATE_OVERVIEW_OPENAPI_SCHEMAS = {
  CertificateOverview: {
    type: "object",
    properties: {
      generatedAt: { type: "string", format: "date-time" },
      certificates: {
        type: "array",
        description: "Soonest expiry first; rows without a known expiry last",
        items: ref("CertificateOverviewRow"),
      },
    },
    required: ["generatedAt", "certificates"],
  },
  CertificateOverviewRow: {
    type: "object",
    properties: {
      id: { type: "string", description: '"acme:<proxy host id>" or "certificate:<certificate id>"' },
      kind: { type: "string", enum: ["acme", "imported", "managed"] },
      certificateId: { type: "integer", nullable: true },
      hostId: { type: "integer", nullable: true, description: "The proxy host an ACME certificate is obtained for" },
      name: { type: "string" },
      domains: { type: "array", items: { type: "string" } },
      active: {
        type: "boolean",
        description: "False for an ACME row whose host is disabled and a managed entry no enabled host uses: Caddy manages no certificate for them",
      },
      issuer: { type: "string", nullable: true },
      issuerFromCertificate: { type: "boolean", description: "False when the issuer is the configured ACME CA, not read from a certificate" },
      keyType: { type: "string", nullable: true, example: "ECDSA P-256" },
      validFrom: { type: "string", format: "date-time", nullable: true },
      validTo: { type: "string", format: "date-time", nullable: true },
      expirySource: { type: "string", enum: ["pem", "caddy"], nullable: true },
      daysLeft: { type: "integer", nullable: true, description: "Whole days left; negative once expired" },
      checkedAt: {
        type: "string",
        format: "date-time",
        nullable: true,
        description: "When Caddy was last asked for the certificate over TLS; null for imported certificates and before the first check",
      },
      issuanceError: {
        type: "object",
        nullable: true,
        description:
          "Why Caddy has no (or no renewed) certificate: its last error for one of the names, while the state is pending, missing, due, overdue or expired. " +
          "Read from the log Caddy writes for this (tls-issuance.log) and sanitized: DNS provider credentials, URLs (reduced to scheme and host), e-mail and IP addresses and long tokens are removed, and the text is cut to 300 characters. Null when Caddy logged none.",
        properties: {
          at: { type: "string", format: "date-time", description: "When Caddy logged it" },
          message: { type: "string" },
        },
        required: ["at", "message"],
      },
      obtainedBy: {
        type: "object",
        properties: {
          method: { type: "string", enum: ["acme", "imported"] },
          challenge: { type: "string", enum: ["http-01", "dns-01"] },
          dnsProvider: { type: "string", nullable: true },
          directory: { type: "string", nullable: true, description: "Host of a custom ACME directory; null for Let's Encrypt" },
        },
        required: ["method"],
      },
      renewal: {
        type: "object",
        properties: {
          state: {
            type: "string",
            enum: [...RENEWAL_STATES],
            description:
              "pending: Caddy has no certificate yet and the host or entry was saved under 15 minutes ago. " +
              "missing: Caddy still has none after that, so obtaining the first one is failing (check Caddy's log, the DNS provider and ports 80/443). " +
              "unknown: Caddy could not be asked or the check has not finished, which says nothing about the certificate.",
          },
          renewFrom: {
            type: "string",
            format: "date-time",
            nullable: true,
            description: "When Caddy starts renewing it: a third of its lifetime before expiry",
          },
        },
        required: ["state", "renewFrom"],
      },
      usedBy: {
        type: "array",
        items: {
          type: "object",
          properties: {
            kind: { type: "string", enum: ["proxy_host", "l4_host"] },
            id: { type: "integer" },
            name: { type: "string" },
            domains: { type: "array", items: { type: "string" } },
          },
          required: ["kind", "id", "name", "domains"],
        },
      },
    },
    required: [
      "id",
      "kind",
      "certificateId",
      "hostId",
      "name",
      "domains",
      "active",
      "issuer",
      "issuerFromCertificate",
      "keyType",
      "validFrom",
      "validTo",
      "expirySource",
      "daysLeft",
      "checkedAt",
      "issuanceError",
      "obtainedBy",
      "renewal",
      "usedBy",
    ],
  },
};
