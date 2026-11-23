import { bundleFromJSON } from "@sigstore/bundle";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { assertNoDuplicateJsonKeys } from "./release-manifest";

const REPOSITORY = "Double-IQ/SentryIQ";
const REPOSITORY_ID = "1345956206";
const WORKFLOW_PATH = ".github/workflows/release.yml";
const PREDICATE_TYPE = "https://slsa.dev/provenance/v1";
const WORKFLOW_SHA_OID = new Uint8Array([0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x13]);

export interface VerifiedReleaseClaims {
  readonly repository: typeof REPOSITORY;
  readonly repositoryId: typeof REPOSITORY_ID;
  readonly version: string;
  readonly sourceCommit: string;
  readonly workflowCommit: string;
  readonly subjectName: string;
  readonly subjectSha256: string;
}

/** Verify the Sigstore bundle first, then apply SentryIQ's exact SLSA/GitHub release policy. */
export function verifyReleaseAttestationBundle(
  bundleJson: string,
  trustedRootJson: string,
  version: string,
  expectedCommit: string,
  expectedSubjectName: string,
  expectedSubjectSha256: string
): VerifiedReleaseClaims {
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version) ||
      !/^[a-f0-9]{40}$/.test(expectedCommit) ||
      !/^[a-f0-9]{64}$/.test(expectedSubjectSha256)) {
    throw new Error("expected release identity or digest is not canonical");
  }
  const zipName = "sentryiq-" + version + ".zip";
  if (expectedSubjectName !== zipName && expectedSubjectName !== "release-manifest.json") {
    throw new Error("release attestation subject name is not canonical");
  }

  const bundle = bundleFromJSON(parseJsonObject(bundleJson, "Sigstore bundle"));
  const trustedRoot = TrustedRoot.fromJSON(parseJsonObject(trustedRootJson, "Sigstore trusted root"));
  const verifier = new Verifier(toTrustMaterial(trustedRoot), {
    ctlogThreshold: 1,
    tlogThreshold: 1,
    timestampThreshold: 1
  });
  const signer = verifier.verify(toSignedEntity(bundle));
  const expectedIdentity = "https://github.com/" + REPOSITORY + "/" + WORKFLOW_PATH +
    "@refs/tags/v" + version;
  if (signer.identity?.subjectAlternativeName !== expectedIdentity) {
    throw new Error("Sigstore signer identity is not the approved SentryIQ release workflow");
  }

  const envelope = bundle.content?.dsseEnvelope;
  if (!envelope || !(envelope.payload instanceof Uint8Array) || envelope.payload.byteLength < 1 ||
      envelope.payload.byteLength > 5_000_000) {
    throw new Error("verified Sigstore bundle does not contain a bounded DSSE payload");
  }
  const statementText = new TextDecoder("utf-8", { fatal: true }).decode(envelope.payload);
  assertNoDuplicateJsonKeys(statementText);
  const statement: unknown = JSON.parse(statementText);
  if (!isRecord(statement) || statement.predicateType !== PREDICATE_TYPE ||
      !Array.isArray(statement.subject) || statement.subject.length < 1 || statement.subject.length > 2 ||
      !isRecord(statement.predicate)) {
    throw new Error("verified attestation is not a bounded SLSA Provenance v1 statement");
  }

  const subjects = new Map<string, string>();
  for (const raw of statement.subject) {
    if (!isRecord(raw) || typeof raw.name !== "string" || !isRecord(raw.digest) ||
        typeof raw.digest.sha256 !== "string" || !/^[a-f0-9]{64}$/i.test(raw.digest.sha256) ||
        (raw.name !== zipName && raw.name !== "release-manifest.json") || subjects.has(raw.name)) {
      throw new Error("verified attestation contains a malformed, unknown, or duplicate subject");
    }
    subjects.set(raw.name, raw.digest.sha256.toLowerCase());
  }
  if (subjects.size === 2 && (!subjects.has(zipName) || !subjects.has("release-manifest.json"))) {
    throw new Error("multi-subject release attestation must bind both manifest and ZIP");
  }
  if (expectedSubjectName === "release-manifest.json" && !subjects.has(zipName)) {
    throw new Error("manifest attestation must also bind its corresponding ZIP");
  }
  const subjectDigest = subjects.get(expectedSubjectName);
  if (!subjectDigest || subjectDigest !== expectedSubjectSha256) {
    throw new Error("attestation subject name or digest does not match the downloaded release artifact");
  }

  const definition = statement.predicate.buildDefinition;
  const external = isRecord(definition) ? definition.externalParameters : undefined;
  const workflow = isRecord(external) ? external.workflow : undefined;
  const internal = isRecord(definition) ? definition.internalParameters : undefined;
  const github = isRecord(internal) ? internal.github : undefined;
  const dependencies = isRecord(definition) ? definition.resolvedDependencies : undefined;
  const runDetails = statement.predicate.runDetails;
  const builder = isRecord(runDetails) ? runDetails.builder : undefined;
  const tagRef = "refs/tags/v" + version;
  const builderId = "https://github.com/" + REPOSITORY + "/" + WORKFLOW_PATH + "@" + tagRef;
  if (!isRecord(workflow) || !isRecord(github) || !Array.isArray(dependencies) || !isRecord(builder) ||
      workflow.repository !== "https://github.com/" + REPOSITORY ||
      workflow.path !== WORKFLOW_PATH || workflow.ref !== tagRef ||
      String(github.repository_id) !== REPOSITORY_ID || github.event_name !== "push" ||
      github.runner_environment !== "github-hosted" || builder.id !== builderId) {
    throw new Error("SLSA provenance repository, workflow, event, runner, or builder identity is not trusted");
  }

  const sourceCommits: string[] = [];
  for (const dependency of dependencies) {
    if (!isRecord(dependency) || !isRecord(dependency.digest)) continue;
    if (dependency.uri === "git+https://github.com/" + REPOSITORY + "@" + tagRef &&
        typeof dependency.digest.gitCommit === "string") {
      sourceCommits.push(dependency.digest.gitCommit.toLowerCase());
    }
  }
  if (sourceCommits.length !== 1 || sourceCommits[0] !== expectedCommit) {
    throw new Error("SLSA source commit does not match GitHub's independently resolved release tag");
  }

  const verificationMaterial = bundle.verificationMaterial?.content;
  const certificate = verificationMaterial?.$case === "certificate"
    ? verificationMaterial.certificate.rawBytes
    : verificationMaterial?.$case === "x509CertificateChain"
      ? verificationMaterial.x509CertificateChain.certificates[0]?.rawBytes
      : undefined;
  if (!(certificate instanceof Uint8Array)) {
    throw new Error("verified Sigstore bundle does not contain the authenticated Fulcio leaf certificate");
  }
  const workflowCommit = extractWorkflowCommit(certificate);
  if (workflowCommit !== expectedCommit) {
    throw new Error("Fulcio Build Config Digest does not match the approved release workflow commit");
  }

  return {
    repository: REPOSITORY,
    repositoryId: REPOSITORY_ID,
    version,
    sourceCommit: sourceCommits[0]!,
    workflowCommit,
    subjectName: expectedSubjectName,
    subjectSha256: subjectDigest
  };
}

function parseJsonObject(source: string, label: string): Record<string, unknown> {
  if (typeof source !== "string" || source.length < 2 || source.length > 8_000_000) {
    throw new Error(label + " is empty or exceeds its configured size limit");
  }
  assertNoDuplicateJsonKeys(source);
  const parsed: unknown = JSON.parse(source);
  if (!isRecord(parsed)) throw new Error(label + " must be a JSON object");
  return parsed;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractWorkflowCommit(der: Uint8Array): string {
  if (der.byteLength < 1 || der.byteLength > 1_000_000) throw new Error("Fulcio leaf certificate size is invalid");
  const outer = readTlv(der, 0);
  if (outer.tag !== 0x30 || outer.end !== der.byteLength) throw new Error("Fulcio certificate DER envelope is invalid");
  const cert = readChildren(der, outer.content, outer.end);
  if (cert.length !== 3 || cert[0]!.tag !== 0x30) throw new Error("Fulcio certificate structure is invalid");
  const tbs = readChildren(der, cert[0]!.content, cert[0]!.end);
  const containers = tbs.filter((item) => item.tag === 0xa3);
  if (containers.length !== 1) throw new Error("Fulcio certificate must contain one extensions container");
  const wrapper = readTlv(der, containers[0]!.content);
  if (wrapper.tag !== 0x30 || wrapper.end !== containers[0]!.end) throw new Error("Fulcio extensions sequence is malformed");

  const matches: string[] = [];
  for (const extension of readChildren(der, wrapper.content, wrapper.end)) {
    if (extension.tag !== 0x30) throw new Error("Fulcio extension is malformed");
    const fields = readChildren(der, extension.content, extension.end);
    if (fields.length < 2 || fields.length > 3 || fields[0]!.tag !== 0x06) throw new Error("Fulcio extension fields are malformed");
    const oid = der.subarray(fields[0]!.content, fields[0]!.end);
    if (!equalBytes(oid, WORKFLOW_SHA_OID)) continue;
    let valueField = fields[1]!;
    if (valueField.tag === 0x01 && fields.length === 3) {
      if (valueField.end - valueField.content !== 1 || der[valueField.content] !== 0xff) {
        throw new Error("Fulcio Build Config Digest critical flag is not canonical DER TRUE");
      }
      valueField = fields[2]!;
    }
    if (valueField.tag !== 0x04) throw new Error("Fulcio Build Config Digest extension encoding is invalid");
    const value = readTlv(der, valueField.content);
    if (value.tag !== 0x0c || value.end !== valueField.end) throw new Error("Fulcio Build Config Digest must be a DER UTF8String");
    matches.push(new TextDecoder("utf-8", { fatal: true }).decode(der.subarray(value.content, value.end)));
  }
  if (matches.length !== 1) throw new Error("Fulcio certificate must contain exactly one Build Config Digest");
  const normalized = matches[0]!.startsWith("sha1:") ? matches[0]!.slice(5) : matches[0]!;
  if (!/^[a-f0-9]{40}$/i.test(normalized)) throw new Error("Fulcio Build Config Digest is not a full workflow SHA-1");
  return normalized.toLowerCase();
}

interface Tlv { tag: number; content: number; end: number; }

function readTlv(bytes: Uint8Array, offset: number): Tlv {
  if (offset < 0 || offset + 2 > bytes.byteLength) throw new Error("Truncated DER value");
  const tag = bytes[offset]!;
  const first = bytes[offset + 1]!;
  if ((tag & 0x1f) === 0x1f) throw new Error("High-tag-number DER values are unsupported");
  let header = 2;
  let length: number;
  if ((first & 0x80) === 0) length = first;
  else {
    const octets = first & 0x7f;
    if (octets === 0 || octets > 4 || offset + 2 + octets > bytes.byteLength || bytes[offset + 2] === 0) {
      throw new Error("Invalid or non-canonical DER length");
    }
    length = 0;
    for (let i = 0; i < octets; i++) length = length * 256 + bytes[offset + 2 + i]!;
    if (length < 128) throw new Error("Non-canonical DER length");
    header += octets;
  }
  const content = offset + header;
  const end = content + length;
  if (end > bytes.byteLength || end < content) throw new Error("DER value exceeds its enclosing data");
  return { tag, content, end };
}

function readChildren(bytes: Uint8Array, start: number, end: number): Tlv[] {
  const items: Tlv[] = [];
  while (start < end) {
    const item = readTlv(bytes, start);
    if (item.end > end) throw new Error("Nested DER value exceeds its parent");
    items.push(item);
    start = item.end;
  }
  if (start !== end) throw new Error("Malformed DER child sequence");
  return items;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let i = 0; i < a.byteLength; i++) difference |= a[i]! ^ b[i]!;
  return difference === 0;
}
