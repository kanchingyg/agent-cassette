const BLOCKED_HOSTNAMES = new Set([
  "169.254.169.254",
  "169.254.170.2",
  "168.63.129.16",
  "100.100.100.200",
  "metadata.google.internal",
  "metadata.tencentyun.com",
  "169.254.169.254.ipv4.super-int.sub",
  "instance-data",
]);

export const ALLOWED_UPSTREAM_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "host.docker.internal",
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "api.deepseek.com",
  "dashscope.aliyuncs.com",
  "api.moonshot.cn",
  "open.bigmodel.cn",
  "api.minimax.chat",
  "api.siliconflow.cn",
  "openrouter.ai",
  "api.together.xyz",
  "api.groq.com",
  "api.fireworks.ai",
  "api.x.ai",
  "api.perplexity.ai",
  "api.cohere.ai",
  "api.mistral.ai",
  "bedrock-runtime.us-east-1.amazonaws.com",
]);

const ALLOWED_UPSTREAM_SUFFIXES = [
  ".openai.azure.com",
  ".cognitiveservices.azure.com",
  ".amazonaws.com",
  ".cloudflare.com",
];

export function isPrivateNetworkHost(hostname: string): boolean {
  const cleanHost = hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");

  if (cleanHost.endsWith(".localhost")) return true;

  if (/^f[cd][0-9a-f]{0,2}:/.test(cleanHost)) return true;
  if (/^fe[89ab][0-9a-f]?:/.test(cleanHost)) return true;
  if (cleanHost === "::") return true;

  const mapped = cleanHost.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mapped) {
    const hi = parseInt(mapped[1], 16);
    const lo = parseInt(mapped[2], 16);
    return isPrivateNetworkHost(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  }

  if (
    cleanHost === "localhost" ||
    cleanHost === "127.0.0.1" ||
    cleanHost === "0.0.0.0" ||
    cleanHost === "0" ||
    cleanHost === "::1" ||
    cleanHost === "0177.0.0.1" ||
    cleanHost === "0x7f000001" ||
    cleanHost === "2130706433"
  ) {
    return true;
  }

  const ipMatch = cleanHost.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!ipMatch) return false;

  const [, o1, o2] = ipMatch.map(Number);
  if (o1 === 0) return true;
  if (o1 === 10) return true;
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
  if (o1 === 192 && o2 === 168) return true;
  if (o1 === 127) return true;
  if (o1 === 100 && o2 >= 64 && o2 <= 127) return true;
  if (o1 === 169 && o2 === 254) return true;
  if (o1 >= 224) return true;
  return false;
}

export function isBlockedSsrfHost(hostname: string): boolean {
  const cleanHost = hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (BLOCKED_HOSTNAMES.has(cleanHost)) return true;

  const ipMatch = cleanHost.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipMatch) {
    const oct1 = Number(ipMatch[1]);
    const oct2 = Number(ipMatch[2]);
    if (oct1 === 169 && oct2 === 254) return true;
  }

  const octalMatch = cleanHost.match(/^0[0-7]+\.0[0-7]+\.0[0-7]+\.0[0-7]+$/);
  if (octalMatch) {
    const parts = cleanHost.split(".").map((p) => parseInt(p, 8));
    if (parts[0] === 169 && parts[1] === 254) return true;
  }

  if (
    cleanHost.startsWith("::ffff:169.254.") ||
    cleanHost.startsWith("fe80:") ||
    cleanHost.startsWith("::ffff:a9fe:")
  ) {
    return true;
  }

  if (
    cleanHost === "2852039166" ||
    cleanHost === "0xa9fea9fe" ||
    cleanHost === "0xa9.0xfe.0xa9.0xfe"
  ) {
    return true;
  }

  return false;
}

export function isNonPublicHost(hostname: string): boolean {
  return isPrivateNetworkHost(hostname) || isBlockedSsrfHost(hostname);
}

function hostOnAllowlist(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (ALLOWED_UPSTREAM_HOSTS.has(h)) return true;
  return ALLOWED_UPSTREAM_SUFFIXES.some((suffix) => h === suffix.slice(1) || h.endsWith(suffix));
}

export function assertAllowedUpstreamTarget(rawUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`SSRF: invalid upstream URL: ${rawUrl}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`SSRF: unsupported protocol: ${parsed.protocol}`);
  }
  const host = parsed.hostname;
  if (isBlockedSsrfHost(host)) {
    throw new Error(`SSRF: blocked metadata or link-local host: ${host}`);
  }
  if (!hostOnAllowlist(host)) {
    throw new Error(`SSRF: host not on allowlist: ${host}`);
  }
  if (isPrivateNetworkHost(host) && !ALLOWED_UPSTREAM_HOSTS.has(host.toLowerCase().replace(/^\[|\]$/g, ""))) {
    throw new Error(`SSRF: private host not allowlisted: ${host}`);
  }
}
