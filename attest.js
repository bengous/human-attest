// Verification logic for human-attestation v2 blocks. No DOM, no network: the
// page and the tests pass in their own OpenPGP.js and their own fetch.
// The format must match human-attest's attestation.ts.

/** @typedef {"issue" | "pr" | "comment" | "review"} Kind */
/** @typedef {{ repo: string, kind: Kind, thread: number | undefined, title: string | undefined }} Attestation */
/** @typedef {{ body: string, attestation: Attestation, armoredSignature: string }} Attested */
/** @typedef {{ found: true } & Attested | { found: false, note: string | undefined }} Split */
/** @typedef {{ owner: string, name: string, number: number, part: { kind: "thread" } | { kind: "comment", id: string } | { kind: "review", id: string } }} Target */
/** @typedef {{ source: "github", repo: string, attestedRepoNow: string | undefined, kind: Kind, title: string | undefined, number: number, author: string | undefined, htmlUrl: string | undefined, body: string }} GithubContext */
/** @typedef {{ source: "pasted" }} PastedContext */
/** @typedef {"pass" | "fail" | "skip"} Status */
/** @typedef {{ id: string, label: string, status: Status, detail: string }} Check */
/** @typedef {{ armoredKey: string, subkeyId: string }} TrustAnchor */
/**
 * @typedef {{
 *   outcome: "absent", note: string | undefined, checks: Check[]
 * } | {
 *   outcome: "valid" | "partial" | "invalid",
 *   checks: Check[],
 *   attestation: Attestation,
 *   signedText: string,
 *   headerText: string,
 *   signedAt: Date | undefined,
 *   issuerKeyId: string | undefined,
 *   fingerprint: string | undefined
 * }} Report
 */

// Only this subkey lives on the YubiKey with a permanent touch policy; a
// signature by another subkey of the same primary key is not an attestation.
export const ATTESTING_SUBKEY_ID = "6e54f320fcca8447";

export const SIGNER_NAME = "Augustin Bengolea";

export const SIGNER_LOGIN = "bengous";

export const SIGNER_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=lTym
-----END PGP PUBLIC KEY BLOCK-----`;

// Signed before the body so an attestation can never double as a git commit or
// tag signature, nor as an artifact-signature, and a v1 block never as a v2 one.
const SIGNATURE_DOMAIN = "human-attestation v2\n";

const BLOCK_START = "<!-- human-attestation v2\n";

const RETIRED_BLOCK_START = "<!-- human-attestation v1\n";

const BLOCK_END = "-->";

const ARMOR_BEGIN = "-----BEGIN PGP SIGNATURE-----";

const KINDS = new Set(["issue", "pr", "comment", "review"]);

const REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\/[A-Za-z0-9._-]+$/;

const THREAD = /^[1-9]\d*$/;

const KIND_NAMES = { issue: "issue", pr: "pull request", comment: "comment", review: "review" };

const DEFAULT_ANCHOR = { armoredKey: SIGNER_KEY, subkeyId: ATTESTING_SUBKEY_ID };

/** @param {string} text */
export function canonicalBody(text) {
  return text.replaceAll("\r\n", "\n").trimEnd();
}

// A comment or a review lives on a thread that already exists; its
// attestation names it, and one that does not never verifies.
/** @param {Kind} kind */
export function isThreaded(kind) {
  return kind === "comment" || kind === "review";
}

/** @param {readonly string[]} lines @returns {{ attestation: Attestation } | { problem: string }} */
function parseHeader(lines) {
  /** @type {Map<string, string>} */
  const fields = new Map();

  for (const line of lines) {
    const colon = line.indexOf(": ");

    if (colon === -1) {
      return { problem: `header line "${line}" is not "field: value"` };
    }

    fields.set(line.slice(0, colon), line.slice(colon + 2));
  }

  const repo = fields.get("repo");
  const kind = fields.get("kind");
  const thread = fields.get("thread");

  if (repo === undefined || !REPO.test(repo)) {
    return { problem: "the header has no valid repo line" };
  }

  if (kind === undefined || !KINDS.has(kind)) {
    return { problem: "the header has no valid kind line" };
  }

  if (thread !== undefined && !THREAD.test(thread)) {
    return { problem: `the thread line "${thread}" is not an issue or pull request number` };
  }

  return {
    attestation: {
      repo,
      kind: /** @type {Kind} */ (kind),
      thread: thread === undefined ? undefined : Number(thread),
      title: fields.get("title"),
    },
  };
}

/** @param {string} normalized */
function absenceNote(normalized) {
  return normalized.includes(`\n${RETIRED_BLOCK_START}`)
    ? "The body carries a human-attestation v1 block. Version 1 is retired: its comment blocks named no thread, so it counts as no attestation."
    : undefined;
}

/** @param {string} text @returns {Split} */
export function splitAttested(text) {
  const normalized = text.replaceAll("\r\n", "\n");
  const at = normalized.lastIndexOf(`\n${BLOCK_START}`);

  if (at === -1) {
    return { found: false, note: absenceNote(normalized) };
  }

  const block = normalized.slice(at + 1 + BLOCK_START.length).trimEnd();

  if (!block.endsWith(BLOCK_END)) {
    return { found: false, note: "An attestation marker is in the text, but not as a block closing the body." };
  }

  const inner = block.slice(0, -BLOCK_END.length);
  const armorAt = inner.indexOf(ARMOR_BEGIN);

  if (armorAt === -1) {
    return { found: false, note: "An attestation marker is in the text, but the block holds no signature." };
  }

  const header = parseHeader(
    inner
      .slice(0, armorAt)
      .split("\n")
      .filter((line) => line !== ""),
  );

  if ("problem" in header) {
    return { found: false, note: `An attestation marker is in the text, but ${header.problem}.` };
  }

  return {
    found: true,
    body: canonicalBody(normalized.slice(0, at)),
    attestation: header.attestation,
    armoredSignature: `${inner.slice(armorAt).trimEnd()}\n`,
  };
}

/** @param {Attestation} attestation */
function headerLines(attestation) {
  const thread = attestation.thread === undefined ? "" : `thread: ${attestation.thread}\n`;
  const title = attestation.title === undefined ? "" : `title: ${attestation.title}\n`;

  return `repo: ${attestation.repo}\nkind: ${attestation.kind}\n${thread}${title}`;
}

/** @param {Attestation} attestation */
function signedHeader(attestation) {
  return `${SIGNATURE_DOMAIN}${headerLines(attestation)}\n`;
}

/** @param {string} body @param {Attestation} attestation */
export function signedPayloadText(body, attestation) {
  return `${signedHeader(attestation)}${canonicalBody(body)}`;
}

/** @param {string} body @param {Attestation} attestation */
export function signedPayload(body, attestation) {
  return new TextEncoder().encode(signedPayloadText(body, attestation));
}

/** @param {string} body @param {Attestation} attestation @param {string} armoredSignature */
export function joinAttested(body, attestation, armoredSignature) {
  return `${canonicalBody(body)}\n\n${BLOCK_START}${headerLines(attestation)}${armoredSignature.trimEnd()}\n${BLOCK_END}\n`;
}

/** @param {string} hex */
export function groupFingerprint(hex) {
  return (hex.toUpperCase().match(/.{1,4}/g) ?? []).join(" ");
}

/** @param {unknown} error */
function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

/** @param {string} message */
function explainSignatureError(message) {
  if (/digest did not match|signature did not match|invalid signature/i.test(message)) {
    return `The text, its header or the signature changed after signing (${message}).`;
  }

  if (/could not find signing key/i.test(message)) {
    return `The signature was not made by any key of ${SIGNER_NAME} (${message}).`;
  }

  return message;
}

/** @param {string} id @param {string} label @param {Status} status @param {string} detail @returns {Check} */
function check(id, label, status, detail) {
  return { id, label, status, detail };
}

/**
 * @param {Attestation} attestation
 * @param {GithubContext | PastedContext} context
 * @returns {Check}
 */
function threadCheck(attestation, context) {
  const label = "Thread matches";

  // Required by the format itself, so it fails even where nothing is compared.
  if (isThreaded(attestation.kind) && attestation.thread === undefined) {
    return check("thread", label, "fail", `The block attests a ${KIND_NAMES[attestation.kind]} but names no thread.`);
  }

  if (context.source === "pasted") {
    return check(
      "thread",
      label,
      "skip",
      attestation.thread === undefined
        ? "Not checked: pasted text. The block names no thread."
        : `Not checked: pasted text. The block claims #${attestation.thread}.`,
    );
  }

  if (!isThreaded(context.kind)) {
    return check("thread", label, "skip", `Not applicable: a ${KIND_NAMES[context.kind]} binds its title instead.`);
  }

  return attestation.thread === context.number
    ? check("thread", label, "pass", `#${context.number}`)
    : check("thread", label, "fail", `Attested for #${attestation.thread}, posted on #${context.number}.`);
}

/**
 * @param {Attestation} attestation
 * @param {GithubContext | PastedContext} context
 * @returns {Check[]}
 */
function placeChecks(attestation, context) {
  if (context.source === "pasted") {
    const skipped = "Not checked: pasted text.";

    return [
      check("repo", "Repository matches", "skip", `${skipped} The block claims ${attestation.repo}.`),
      check("kind", "Kind matches", "skip", `${skipped} The block claims ${KIND_NAMES[attestation.kind]}.`),
      check(
        "title",
        "Title matches",
        "skip",
        attestation.title === undefined ? `${skipped} The block claims no title.` : `${skipped} The block claims "${attestation.title}".`,
      ),
      threadCheck(attestation, context),
    ];
  }

  // GitHub owner and repository names are case-insensitive.
  const repoMatches = attestation.repo.toLowerCase() === context.repo.toLowerCase();
  const kindMatches = attestation.kind === context.kind;

  return [
    repoMatches
      ? check("repo", "Repository matches", "pass", context.repo)
      : check(
          "repo",
          "Repository matches",
          "fail",
          context.attestedRepoNow?.toLowerCase() === context.repo.toLowerCase()
            ? `Attested for ${attestation.repo}, published on ${context.repo}. GitHub redirects ${attestation.repo} there: the repository was renamed or transferred after the attestation, which still names the old place.`
            : `Attested for ${attestation.repo}, published on ${context.repo}.`,
        ),
    kindMatches
      ? check("kind", "Kind matches", "pass", KIND_NAMES[context.kind])
      : check(
          "kind",
          "Kind matches",
          "fail",
          `Attested as ${KIND_NAMES[attestation.kind]}, published as ${KIND_NAMES[context.kind]}.`,
        ),
    isThreaded(context.kind)
      ? check("title", "Title matches", "skip", `Not applicable: a ${KIND_NAMES[context.kind]} has no title.`)
      : attestation.title === context.title
        ? check("title", "Title matches", "pass", `"${context.title}"`)
        : check(
            "title",
            "Title matches",
            "fail",
            attestation.title === undefined
              ? `The block attests no title; the ${KIND_NAMES[context.kind]} is titled "${context.title}".`
              : `Attested title "${attestation.title}", published title "${context.title}". The title changed after the attestation.`,
          ),
    threadCheck(attestation, context),
  ];
}

/**
 * @param {typeof import("openpgp")} openpgp
 * @param {TrustAnchor} [anchor] the key and subkey to trust; the tests pass their own
 * @returns {(text: string, context: GithubContext | PastedContext) => Promise<Report>}
 */
export function makeVerifier(openpgp, anchor = DEFAULT_ANCHOR) {
  const signerKey = openpgp.readKey({ armoredKey: anchor.armoredKey });
  const pinnedId = anchor.subkeyId;

  return async (text, context) => {
    const split = splitAttested(text);

    if (!split.found) {
      return {
        outcome: "absent",
        note: split.note,
        checks: [
          check(
            "block",
            "Attestation block present",
            "fail",
            split.note ?? "The raw body does not end with a human-attestation block.",
          ),
        ],
      };
    }

    const { body, attestation, armoredSignature } = split;
    const key = await signerKey;

    /** @type {Date | undefined} */
    let signedAt;
    /** @type {string | undefined} */
    let issuerKeyId;
    /** @type {string | null} */
    let signatureProblem;

    try {
      const signature = await openpgp.readSignature({ armoredSignature });
      const [packet] = signature.packets;
      signedAt = packet?.created ?? undefined;
      issuerKeyId = packet?.issuerKeyID.toHex();

      const { signatures } = await openpgp.verify({
        message: await openpgp.createMessage({ binary: signedPayload(body, attestation) }),
        signature,
        verificationKeys: key,
        expectSigned: true,
      });

      const [first] = signatures;

      if (first === undefined) {
        signatureProblem = "The block holds no signature.";
      } else {
        await first.verified;
        issuerKeyId = first.keyID.toHex();
        signatureProblem = null;
      }
    } catch (error) {
      signatureProblem = explainSignatureError(messageOf(error));
    }

    const fingerprint = key
      .getKeys()
      .find((candidate) => candidate.getKeyID().toHex() === issuerKeyId)
      ?.getFingerprint();
    const pinned = issuerKeyId === pinnedId;

    const checks = [
      check("block", "Attestation block present", "pass", "The raw body ends with a human-attestation v2 block."),
      signatureProblem === null
        ? check("signature", "Signature valid", "pass", `Made over the exact text below by a key of ${SIGNER_NAME}.`)
        : check("signature", "Signature valid", "fail", signatureProblem),
      pinned && signatureProblem === null
        ? check("subkey", "Signed by the pinned subkey", "pass", `Subkey ${pinnedId}, the one held on the YubiKey.`)
        : pinned
          ? check("subkey", "Signed by the pinned subkey", "fail", "The signature names the pinned subkey but does not verify against it.")
          : check(
              "subkey",
              "Signed by the pinned subkey",
              "fail",
              issuerKeyId === undefined
                ? "The signature names no issuer subkey."
                : `Signed by ${issuerKeyId}, not by the YubiKey subkey ${pinnedId}.`,
            ),
      ...placeChecks(attestation, context),
    ];

    const failed = checks.some((item) => item.status === "fail");

    return {
      outcome: failed ? "invalid" : context.source === "pasted" ? "partial" : "valid",
      checks,
      attestation,
      signedText: signedPayloadText(body, attestation),
      headerText: signedHeader(attestation),
      signedAt,
      issuerKeyId,
      fingerprint,
    };
  };
}

const URL_PATH = /^\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)\/(issues|pull)\/(\d+)(?:\/[^?#]*)?$/;

/** @param {string} input @returns {{ ok: true, target: Target } | { ok: false, reason: string }} */
export function parseGithubUrl(input) {
  const trimmed = input.trim();
  const expected =
    "Expected a link like https://github.com/owner/repo/issues/12, …/pull/34, or either one followed by #issuecomment-5678.";

  /** @type {URL} */
  let url;

  try {
    url = new URL(/^[a-z]+:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
  } catch {
    return { ok: false, reason: `That is not a URL. ${expected}` };
  }

  if (url.hostname !== "github.com" && url.hostname !== "www.github.com") {
    return { ok: false, reason: `The link points to ${url.hostname}, not github.com. ${expected}` };
  }

  const match = URL_PATH.exec(url.pathname);

  if (match === null) {
    return { ok: false, reason: `The link is not an issue or a pull request. ${expected}` };
  }

  const [, owner = "", name = "", , number = ""] = match;
  const hash = url.hash.slice(1);
  const comment = /^issuecomment-(\d+)$/.exec(hash);
  const review = /^pullrequestreview-(\d+)$/.exec(hash);

  /** @type {Target["part"]} */
  let part = { kind: "thread" };

  if (comment !== null) {
    part = { kind: "comment", id: comment[1] ?? "" };
  } else if (review !== null) {
    part = { kind: "review", id: review[1] ?? "" };
  } else if (hash !== "" && !/^issue-\d+$/.test(hash)) {
    return {
      ok: false,
      reason: `The link points to #${hash}, which this page cannot read. Link the issue, the pull request, or one of its top-level comments (#issuecomment-…).`,
    };
  }

  return { ok: true, target: { owner, name, number: Number(number), part } };
}

/** @param {Target} target */
export function apiUrlFor(target) {
  const repo = `https://api.github.com/repos/${target.owner}/${target.name}`;

  switch (target.part.kind) {
    case "thread":
      return `${repo}/issues/${target.number}`;
    case "comment":
      return `${repo}/issues/comments/${target.part.id}`;
    case "review":
      return `${repo}/pulls/${target.number}/reviews/${target.part.id}`;
  }
}

/** @param {Target} target */
export function rawBodyCommand(target) {
  return `gh api ${apiUrlFor(target).replace("https://api.github.com/", "")} --jq .body`;
}

/** @param {string} repo */
export function repoApiUrl(repo) {
  return `https://api.github.com/repos/${repo}`;
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** @param {unknown} url */
function repoOfApiUrl(url) {
  const match = typeof url === "string" ? /^https:\/\/api\.github\.com\/repos\/([^/]+\/[^/]+)/.exec(url) : null;

  return match?.[1];
}

/** @param {unknown} url */
function numberOfApiUrl(url) {
  const match = typeof url === "string" ? /\/(?:issues|pulls)\/(\d+)$/.exec(url) : null;

  return match?.[1] === undefined ? undefined : Number(match[1]);
}

/**
 * Where the text was published, read from the API response rather than the
 * link, so a renamed repository or a transferred issue reports its real home.
 * @param {Target} target
 * @param {unknown} json
 * @returns {GithubContext}
 */
export function contextFromApi(target, json) {
  if (!isRecord(json)) {
    throw new Error("GitHub returned something other than an issue, pull request or comment.");
  }

  const body = typeof json["body"] === "string" ? json["body"] : "";
  const author = isRecord(json["user"]) && typeof json["user"]["login"] === "string" ? json["user"]["login"] : undefined;
  const htmlUrl = typeof json["html_url"] === "string" ? json["html_url"] : undefined;
  const linkRepo = `${target.owner}/${target.name}`;

  switch (target.part.kind) {
    case "thread":
      return {
        source: "github",
        repo: repoOfApiUrl(json["repository_url"]) ?? linkRepo,
        attestedRepoNow: undefined,
        kind: isRecord(json["pull_request"]) ? "pr" : "issue",
        title: typeof json["title"] === "string" ? json["title"] : undefined,
        number: typeof json["number"] === "number" ? json["number"] : target.number,
        author,
        htmlUrl,
        body,
      };
    case "comment":
      return {
        source: "github",
        repo: repoOfApiUrl(json["issue_url"]) ?? linkRepo,
        attestedRepoNow: undefined,
        kind: "comment",
        title: undefined,
        number: numberOfApiUrl(json["issue_url"]) ?? target.number,
        author,
        htmlUrl,
        body,
      };
    case "review":
      return {
        source: "github",
        repo: repoOfApiUrl(json["pull_request_url"]) ?? linkRepo,
        attestedRepoNow: undefined,
        kind: "review",
        title: undefined,
        number: numberOfApiUrl(json["pull_request_url"]) ?? target.number,
        author,
        htmlUrl,
        body,
      };
  }
}

/**
 * @param {Target} target
 * @param {number} status
 * @param {{ get(name: string): string | null }} headers
 * @param {Date} now
 */
export function describeHttpError(target, status, headers, now) {
  const paste = `Run ${rawBodyCommand(target)} and paste its output in the Markdown field instead.`;
  const remaining = headers.get("x-ratelimit-remaining");

  if ((status === 403 || status === 429) && (remaining === "0" || headers.get("retry-after") !== null)) {
    const reset = Number(headers.get("x-ratelimit-reset"));
    const minutes = Number.isFinite(reset) && reset > 0 ? Math.max(1, Math.ceil((reset * 1000 - now.getTime()) / 60000)) : undefined;
    const when = minutes === undefined ? "within the hour" : `in about ${minutes} minute${minutes === 1 ? "" : "s"}`;

    return `GitHub's anonymous API limit (60 requests per hour per network address) is used up. It resets ${when}. ${paste}`;
  }

  if (status === 404) {
    return `GitHub found nothing at that link. Either it is wrong, or the repository is private: this page reads public repositories only, without signing in. ${paste}`;
  }

  if (status === 410) {
    return "GitHub says this was deleted. There is no text left to verify.";
  }

  if (status === 401 || status === 403) {
    return `GitHub refused the anonymous read (HTTP ${status}). ${paste}`;
  }

  return `GitHub answered HTTP ${status}. Try again in a minute, or: ${paste}`;
}
