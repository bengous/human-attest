import { beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as openpgp from "openpgp";
import {
  ATTESTING_SUBKEY_ID,
  SIGNER_KEY,
  apiUrlFor,
  canonicalBody,
  contextFromApi,
  describeHttpError,
  joinAttested,
  makeVerifier,
  parseGithubUrl,
  signedPayload,
  signedPayloadText,
  splitAttested,
} from "../attest.js";

const here = new URL(".", import.meta.url);

/** @param {string} name */
function fixture(name) {
  return JSON.parse(readFileSync(new URL(`fixtures/${name}`, here), "utf8"));
}

// Real publications on bengous/human-attest, attested in format v1 before the
// repository was renamed from human-attest-test. v2 reads them as no attestation.
const issueJson = fixture("issue-1.api.json");
const commentJson = fixture("comment-6584215389.api.json");

const issueTarget = { owner: "bengous", name: "human-attest", number: 1, part: { kind: "thread" } };
const commentTarget = { owner: "bengous", name: "human-attest", number: 1, part: { kind: "comment", id: "6584215389" } };

const v1IssueContext = contextFromApi(issueTarget, issueJson);
const v1CommentContext = contextFromApi(commentTarget, commentJson);

const realVerify = makeVerifier(openpgp);

const REAL_PINNED_FINGERPRINT = "6376ab0b983273077d0abff66e54f320fcca8447";

const ISSUE_TEXT =
  "**Steps**\nRun `make` on arm64.\n\n**Result**\nThe linker fails with an undefined symbol.\n\n---\nDrafted with an agent, read and approved by the account owner with a hardware key touch.";

const COMMENT_TEXT = "Confirmed on a second machine: the build fails the same way with a clean checkout.";

/** @type {import("../attest.js").GithubContext} */
const issueContext = { ...v1IssueContext, title: "Linker fails on arm64" };

/** @type {import("../attest.js").GithubContext} */
const commentContext = { ...v1CommentContext };

const issueClaim = { repo: "bengous/human-attest", kind: "issue", thread: undefined, title: "Linker fails on arm64" };
const commentClaim = { repo: "bengous/human-attest", kind: "comment", thread: 1, title: undefined };

/** @type {openpgp.PrivateKey} */
let privateKey;
/** @type {string} */
let signingSubkeyId;
/** @type {(text: string, context: any) => Promise<import("../attest.js").Report>} */
let verify;

// No YubiKey here: a key generated for the test stands in for the real one,
// with its own signing subkey pinned the way the page pins the card's, and
// the card's algorithm (EdDSA on ed25519, v4 key).
beforeAll(async () => {
  const generated = await openpgp.generateKey({
    type: "ecc",
    curve: "ed25519Legacy",
    userIDs: [{ name: "Test signer", email: "test@example.invalid" }],
    subkeys: [{}, { sign: true }],
    format: "object",
  });
  privateKey = generated.privateKey;
  const signing = privateKey.subkeys.find((subkey) => subkey.getAlgorithmInfo().algorithm === "eddsaLegacy");
  if (signing === undefined) throw new Error("the generated key has no signing subkey");
  signingSubkeyId = signing.getKeyID().toHex();
  verify = makeVerifier(openpgp, { armoredKey: generated.publicKey.armor(), subkeyId: signingSubkeyId });
});

/**
 * @param {string} body
 * @param {import("../attest.js").Attestation} claim
 * @param {{ signedClaim?: import("../attest.js").Attestation, byPrimary?: boolean }} [options]
 */
async function attest(body, claim, options = {}) {
  const signingKeyID = options.byPrimary ? privateKey.getKeyID() : privateKey.subkeys.find((s) => s.getKeyID().toHex() === signingSubkeyId)?.getKeyID();
  const signature = await openpgp.sign({
    message: await openpgp.createMessage({ binary: signedPayload(body, options.signedClaim ?? claim) }),
    signingKeys: privateKey,
    signingKeyIDs: signingKeyID === undefined ? [] : [signingKeyID],
    detached: true,
    format: "armored",
  });

  return joinAttested(body, claim, signature);
}

/** @param {import("../attest.js").Report} report */
function statuses(report) {
  return Object.fromEntries(report.checks.map((item) => [item.id, item.status]));
}

/** @param {import("../attest.js").Report} report @param {string} id */
function detail(report, id) {
  return report.checks.find((item) => item.id === id)?.detail;
}

describe("real v1 publications", () => {
  test("the v1 issue reads as no attestation, with a note", async () => {
    expect(issueJson.body).toContain("<!-- human-attestation v1\n");

    const report = await realVerify(v1IssueContext.body, v1IssueContext);

    expect(report.outcome).toBe("absent");
    if (report.outcome !== "absent") throw new Error("unreachable");
    expect(report.note).toContain("v1 block");
    expect(statuses(report)).toEqual({ block: "fail" });
  });

  test("the v1 comment reads as no attestation", async () => {
    expect((await realVerify(v1CommentContext.body, v1CommentContext)).outcome).toBe("absent");
    expect((await realVerify(v1CommentContext.body, { source: "pasted" })).outcome).toBe("absent");
  });

  test("the page's anchor is the YubiKey subkey", async () => {
    const key = await openpgp.readKey({ armoredKey: SIGNER_KEY });
    const subkey = key.getKeys().find((candidate) => candidate.getKeyID().toHex() === ATTESTING_SUBKEY_ID);

    expect(subkey?.getFingerprint()).toBe(REAL_PINNED_FINGERPRINT);
  });

  test("a block signed by another key fails against the real anchor", async () => {
    const report = await realVerify(await attest(COMMENT_TEXT, commentClaim), commentContext);

    expect(report.outcome).toBe("invalid");
    expect(statuses(report)).toMatchObject({ signature: "fail", subkey: "fail" });
    expect(detail(report, "signature")).toContain("not made by any key");
  });
});

describe("valid v2 attestations", () => {
  test("an issue passes six checks, the thread being not applicable", async () => {
    const report = await verify(await attest(ISSUE_TEXT, issueClaim), issueContext);

    expect(report.outcome).toBe("valid");
    expect(statuses(report)).toEqual({
      block: "pass",
      signature: "pass",
      subkey: "pass",
      repo: "pass",
      kind: "pass",
      title: "pass",
      thread: "skip",
    });
    if (report.outcome === "absent") throw new Error("unreachable");
    expect(report.issuerKeyId).toBe(signingSubkeyId);
    expect(report.signedAt).toBeInstanceOf(Date);
    expect(report.signedText).toBe(`human-attestation v2\nrepo: bengous/human-attest\nkind: issue\ntitle: Linker fails on arm64\n\n${ISSUE_TEXT}`);
  });

  test("a comment passes on its thread, the title being not applicable", async () => {
    const report = await verify(await attest(COMMENT_TEXT, commentClaim), commentContext);

    expect(report.outcome).toBe("valid");
    expect(statuses(report)).toMatchObject({ signature: "pass", subkey: "pass", repo: "pass", kind: "pass", title: "skip", thread: "pass" });
    expect(detail(report, "thread")).toBe("#1");
    if (report.outcome === "absent") throw new Error("unreachable");
    expect(report.headerText).toBe("human-attestation v2\nrepo: bengous/human-attest\nkind: comment\nthread: 1\n\n");
  });

  test("pasted text checks the signature and leaves the place unchecked", async () => {
    const report = await verify(await attest(COMMENT_TEXT, commentClaim), { source: "pasted" });

    expect(report.outcome).toBe("partial");
    expect(statuses(report)).toEqual({
      block: "pass",
      signature: "pass",
      subkey: "pass",
      repo: "skip",
      kind: "skip",
      title: "skip",
      thread: "skip",
    });
    expect(detail(report, "thread")).toBe("Not checked: pasted text. The block claims #1.");
  });
});

describe("the thread binding", () => {
  test("a comment attested for another thread fails", async () => {
    const report = await verify(await attest(COMMENT_TEXT, { ...commentClaim, thread: 2 }), commentContext);

    expect(report.outcome).toBe("invalid");
    expect(statuses(report)).toMatchObject({ signature: "pass", thread: "fail" });
    expect(detail(report, "thread")).toBe("Attested for #2, posted on #1.");
  });

  test("a correctly signed comment block without a thread never verifies", async () => {
    const unthreaded = { ...commentClaim, thread: undefined };
    const body = await attest(COMMENT_TEXT, unthreaded);

    const onGithub = await verify(body, commentContext);
    const pasted = await verify(body, { source: "pasted" });

    expect(onGithub.outcome).toBe("invalid");
    expect(statuses(onGithub)).toMatchObject({ signature: "pass", thread: "fail" });
    expect(detail(onGithub, "thread")).toBe("The block attests a comment but names no thread.");
    expect(pasted.outcome).toBe("invalid");
    expect(statuses(pasted)).toMatchObject({ signature: "pass", thread: "fail" });
  });

  test("a review block without a thread fails the same way", async () => {
    const reviewContext = { ...commentContext, kind: "review" };
    const report = await verify(await attest(COMMENT_TEXT, { ...commentClaim, kind: "review", thread: undefined }), reviewContext);

    expect(statuses(report)).toMatchObject({ kind: "pass", thread: "fail" });
  });

  test("rewriting the thread line breaks the signature", async () => {
    const body = (await attest(COMMENT_TEXT, commentClaim)).replace("thread: 1\n", "thread: 7\n");
    const report = await verify(body, { ...commentContext, number: 7 });

    expect(statuses(report)).toMatchObject({ signature: "fail", thread: "pass" });
  });

  test("a thread line that is not a number makes the block unreadable", () => {
    for (const thread of ["0", "07", "abc", "-3"]) {
      const split = splitAttested(`x\n\n<!-- human-attestation v2\nrepo: o/n\nkind: comment\nthread: ${thread}\n-----BEGIN PGP SIGNATURE-----\n\nAA==\n-----END PGP SIGNATURE-----\n-->\n`);
      expect(split.found).toBe(false);
    }
  });
});

describe("tampering and misuse", () => {
  test("one changed word breaks the signature", async () => {
    const body = await attest(ISSUE_TEXT, issueClaim);
    const tampered = body.replace("undefined symbol", "missing symbol");
    expect(tampered).not.toBe(body);

    const report = await verify(tampered, issueContext);

    expect(report.outcome).toBe("invalid");
    expect(statuses(report)).toMatchObject({ signature: "fail", subkey: "fail", repo: "pass", kind: "pass", title: "pass" });
    expect(detail(report, "signature")).toContain("changed after signing");
  });

  test("a rewritten repo header fails both the signature and the repository check", async () => {
    const forged = (await attest(ISSUE_TEXT, issueClaim)).replace("repo: bengous/human-attest\n", "repo: someone/elsewhere\n");

    const report = await verify(forged, issueContext);

    expect(statuses(report)).toMatchObject({ signature: "fail", repo: "fail" });
    expect(detail(report, "repo")).toBe("Attested for someone/elsewhere, published on bengous/human-attest.");
  });

  test("a signature by another subkey of the same key fails the pinned-subkey check", async () => {
    const report = await verify(await attest(ISSUE_TEXT, issueClaim, { byPrimary: true }), issueContext);

    expect(report.outcome).toBe("invalid");
    expect(statuses(report)).toMatchObject({ signature: "pass", subkey: "fail" });
  });

  test("an intact block reposted on another repository fails only the place checks", async () => {
    const report = await verify(await attest(ISSUE_TEXT, issueClaim), { ...issueContext, repo: "someone/elsewhere" });

    expect(statuses(report)).toMatchObject({ signature: "pass", subkey: "pass", repo: "fail", kind: "pass" });
  });

  test("an issue block reposted as a comment fails the kind check", async () => {
    const report = await verify(await attest(ISSUE_TEXT, issueClaim), commentContext);

    expect(statuses(report)).toMatchObject({ signature: "pass", kind: "fail" });
  });

  test("a retitled issue fails the title check", async () => {
    const report = await verify(await attest(ISSUE_TEXT, issueClaim), { ...issueContext, title: "Something else" });

    expect(statuses(report)).toMatchObject({ signature: "pass", title: "fail" });
  });

  test("a repository renamed after the attestation fails the repository check and says why", async () => {
    const old = { ...issueClaim, repo: "bengous/human-attest-test" };
    const body = await attest(ISSUE_TEXT, old);

    const plain = await verify(body, issueContext);
    const explained = await verify(body, { ...issueContext, attestedRepoNow: "bengous/human-attest" });

    expect(detail(plain, "repo")).toBe("Attested for bengous/human-attest-test, published on bengous/human-attest.");
    expect(statuses(explained)).toMatchObject({ signature: "pass", repo: "fail" });
    expect(detail(explained, "repo")).toContain("renamed or transferred after the attestation");
  });

  test("repository names compare without case", async () => {
    const report = await verify(await attest(ISSUE_TEXT, issueClaim), { ...issueContext, repo: "Bengous/Human-Attest" });

    expect(report.outcome).toBe("valid");
  });
});

describe("format", () => {
  test("CRLF line endings verify like LF", async () => {
    const crlf = (await attest(ISSUE_TEXT, issueClaim)).replaceAll("\n", "\r\n");

    expect((await verify(crlf, issueContext)).outcome).toBe("valid");
  });

  test("a body signed with CRLF verifies with LF", async () => {
    const body = await attest(ISSUE_TEXT.replaceAll("\n", "\r\n"), issueClaim);

    expect((await verify(body.replaceAll("\r\n", "\n"), issueContext)).outcome).toBe("valid");
  });

  test("trailing whitespace after the block is ignored", async () => {
    const report = await verify(`${await attest(COMMENT_TEXT, commentClaim)}\n\n  \n`, commentContext);

    expect(report.outcome).toBe("valid");
  });

  test("a body without a block is absent, not an error", async () => {
    const report = await verify("Hello,\n\nthe build fails on arm64. Logs attached.\n", issueContext);

    expect(report).toEqual({
      outcome: "absent",
      note: undefined,
      checks: [
        {
          id: "block",
          label: "Attestation block present",
          status: "fail",
          detail: "The raw body does not end with a human-attestation block.",
        },
      ],
    });
  });

  test("a marker that does not close the body counts as absent, with a note", async () => {
    const report = await verify(`${await attest(COMMENT_TEXT, commentClaim)}\nThanks!\n`, commentContext);

    expect(report.outcome).toBe("absent");
    if (report.outcome !== "absent") throw new Error("unreachable");
    expect(report.note).toContain("not as a block closing the body");
  });

  test("an unknown kind makes the block unreadable", async () => {
    const body = (await attest(ISSUE_TEXT, issueClaim)).replace("kind: issue", "kind: gist");

    expect(splitAttested(body).found).toBe(false);
  });

  test("the payload matches the documented layout", () => {
    expect(signedPayloadText("body  \r\nline\n\n", { repo: "o/n", kind: "issue", thread: undefined, title: "T" })).toBe(
      "human-attestation v2\nrepo: o/n\nkind: issue\ntitle: T\n\nbody  \nline",
    );
    expect(signedPayloadText("x", { repo: "o/n", kind: "comment", thread: 42, title: undefined })).toBe(
      "human-attestation v2\nrepo: o/n\nkind: comment\nthread: 42\n\nx",
    );
    expect(canonicalBody("a\r\nb \t\n\n")).toBe("a\nb");
  });

  test("a joined block splits back into the same parts", () => {
    const armor = "-----BEGIN PGP SIGNATURE-----\n\nAA==\n-----END PGP SIGNATURE-----\n";
    const joined = joinAttested("hi \n", commentClaim, armor);

    expect(joined).toBe(`hi\n\n<!-- human-attestation v2\nrepo: bengous/human-attest\nkind: comment\nthread: 1\n${armor}-->\n`);
    expect(splitAttested(joined)).toEqual({ found: true, body: "hi", attestation: commentClaim, armoredSignature: armor });
  });
});

describe("links and API responses", () => {
  test("issue, pull request, comment and review links resolve to API URLs", () => {
    const cases = {
      "https://github.com/bengous/human-attest/issues/1": "https://api.github.com/repos/bengous/human-attest/issues/1",
      "github.com/o/r/pull/7/files": "https://api.github.com/repos/o/r/issues/7",
      "https://github.com/o/r.js/issues/3#issuecomment-99": "https://api.github.com/repos/o/r.js/issues/comments/99",
      "https://github.com/o/r/pull/3#issuecomment-99": "https://api.github.com/repos/o/r/issues/comments/99",
      "https://github.com/o/r/pull/3#pullrequestreview-42": "https://api.github.com/repos/o/r/pulls/3/reviews/42",
      "https://github.com/o/r/issues/3#issue-123": "https://api.github.com/repos/o/r/issues/3",
    };

    for (const [link, api] of Object.entries(cases)) {
      const parsed = parseGithubUrl(link);
      if (!parsed.ok) throw new Error(`${link}: ${parsed.reason}`);
      expect(apiUrlFor(parsed.target)).toBe(api);
    }
  });

  test("other links are refused with a reason", () => {
    for (const link of [
      "https://gitlab.com/o/r/issues/1",
      "https://github.com/o/r",
      "https://github.com/o/r/discussions/4",
      "https://github.com/o/r/pull/3#discussion_r55",
      "not a url at all",
    ]) {
      expect(parseGithubUrl(link).ok).toBe(false);
    }
  });

  test("the context comes from the API response", () => {
    expect(v1IssueContext).toMatchObject({
      source: "github",
      repo: "bengous/human-attest",
      attestedRepoNow: undefined,
      kind: "issue",
      title: "Attested test issue: hidden signature block and verification",
      author: "bengous",
      number: 1,
    });
    expect(v1CommentContext).toMatchObject({ repo: "bengous/human-attest", kind: "comment", title: undefined, number: 1 });
    expect(contextFromApi(issueTarget, { ...issueJson, pull_request: { url: "x" } }).kind).toBe("pr");
  });

  test("a comment's or a review's thread comes from the API, not the link", () => {
    const misnumbered = { ...commentTarget, number: 99 };
    const review = { owner: "o", name: "r", number: 99, part: { kind: "review", id: "5" } };

    expect(contextFromApi(misnumbered, commentJson).number).toBe(1);
    expect(contextFromApi(review, { body: "", pull_request_url: "https://api.github.com/repos/o/r/pulls/12" })).toMatchObject({
      kind: "review",
      repo: "o/r",
      number: 12,
    });
    expect(contextFromApi(misnumbered, { ...commentJson, issue_url: undefined }).number).toBe(99);
  });

  test("an exhausted rate limit says when it resets and how to read the body instead", () => {
    const now = new Date("2026-11-02T12:00:00Z");
    const headers = new Headers({ "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(now.getTime() / 1000 + 600) });

    const message = describeHttpError(issueTarget, 403, headers, now);

    expect(message).toContain("60 requests per hour");
    expect(message).toContain("in about 10 minutes");
    expect(message).toContain("gh api repos/bengous/human-attest/issues/1 --jq .body");
  });

  test("a 404 mentions private repositories", () => {
    expect(describeHttpError(commentTarget, 404, new Headers(), new Date())).toContain("private");
  });
});

describe("the page", () => {
  const html = readFileSync(new URL("../index.html", here), "utf8");

  /** @param {string} algorithm @param {string | Buffer} data */
  function digest(algorithm, data) {
    return createHash(algorithm).update(data).digest("base64");
  }

  test("pins the same OpenPGP.js file the tests ran against", () => {
    const local = readFileSync(new URL("../node_modules/openpgp/dist/openpgp.min.js", here));
    const tag = /<script src="(https:\/\/cdn\.jsdelivr\.net\/npm\/openpgp@6\.3\.2\/dist\/openpgp\.min\.js)" integrity="([^"]+)" crossorigin="anonymous"><\/script>/.exec(html);

    expect(tag).not.toBeNull();
    expect(tag?.[2]).toBe(`sha384-${digest("sha384", local)}`);
    expect(JSON.parse(readFileSync(new URL("../node_modules/openpgp/package.json", here), "utf8")).version).toBe("6.3.2");
  });

  test("its Content-Security-Policy hashes match the inline script and style", () => {
    const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1] ?? "";
    const script = /<script type="module">([\s\S]*?)<\/script>/.exec(html)?.[1];
    const style = /<style>([\s\S]*?)<\/style>/.exec(html)?.[1];

    expect(script).toBeDefined();
    expect(style).toBeDefined();
    expect(csp).toContain(`'sha256-${digest("sha256", script ?? "")}'`);
    expect(csp).toContain(`'sha256-${digest("sha256", style ?? "")}'`);
  });
});
