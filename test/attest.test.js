import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as openpgp from "openpgp";
import {
  ATTESTING_SUBKEY_ID,
  apiUrlFor,
  canonicalBody,
  contextFromApi,
  describeHttpError,
  makeVerifier,
  parseGithubUrl,
  signedPayloadText,
  splitAttested,
} from "../attest.js";

const here = new URL(".", import.meta.url);

/** @param {string} name */
function fixture(name) {
  return JSON.parse(readFileSync(new URL(`fixtures/${name}`, here), "utf8"));
}

const issueJson = fixture("issue-1.api.json");
const commentJson = fixture("comment-6584215389.api.json");

const issueTarget = { owner: "bengous", name: "human-attest-test", number: 1, part: { kind: "thread" } };
const commentTarget = { owner: "bengous", name: "human-attest-test", number: 1, part: { kind: "comment", id: "6584215389" } };

// The fixtures were fetched right after bengous/human-attest-test was renamed
// to bengous/human-attest: the API answers with the new name, the attestations
// name the old one. The contexts below restore the place they were published.
// Without its lookup of the attested name, the rename reads as a plain mismatch.
const renamedIssueContext = contextFromApi(issueTarget, issueJson);
const issueContext = { ...renamedIssueContext, repo: "bengous/human-attest-test" };
const commentContext = { ...contextFromApi(commentTarget, commentJson), repo: "bengous/human-attest-test" };

const verify = makeVerifier(openpgp);

const PINNED_FINGERPRINT = "6376ab0b983273077d0abff66e54f320fcca8447";

/** @param {import("../attest.js").Report} report */
function statuses(report) {
  return Object.fromEntries(report.checks.map((item) => [item.id, item.status]));
}

describe("real attested publications", () => {
  test("the issue verifies against its thread", async () => {
    const report = await verify(issueContext.body, issueContext);

    expect(report.outcome).toBe("valid");
    expect(statuses(report)).toEqual({
      block: "pass",
      signature: "pass",
      subkey: "pass",
      repo: "pass",
      kind: "pass",
      title: "pass",
    });
    if (report.outcome === "absent") throw new Error("unreachable");
    expect(report.issuerKeyId).toBe(ATTESTING_SUBKEY_ID);
    expect(report.fingerprint).toBe(PINNED_FINGERPRINT);
    expect(report.signedAt).toBeInstanceOf(Date);
    expect(report.signedText.startsWith("human-attestation v1\nrepo: bengous/human-attest-test\nkind: issue\ntitle: ")).toBe(true);
    expect(report.signedText.endsWith("hardware key touch.")).toBe(true);
    expect(report.signedText).not.toContain("<!--");
  });

  test("the comment verifies, with no title to compare", async () => {
    const report = await verify(commentContext.body, commentContext);

    expect(report.outcome).toBe("valid");
    expect(statuses(report)).toMatchObject({ signature: "pass", subkey: "pass", repo: "pass", kind: "pass", title: "skip" });
  });

  test("pasted text checks the signature and reports the place as not checked", async () => {
    const report = await verify(issueContext.body, { source: "pasted" });

    expect(report.outcome).toBe("partial");
    expect(statuses(report)).toEqual({
      block: "pass",
      signature: "pass",
      subkey: "pass",
      repo: "skip",
      kind: "skip",
      title: "skip",
    });
    expect(report.checks.find((item) => item.id === "repo")?.detail).toStartWith("Not checked: pasted text.");
  });
});

describe("tampering and misuse", () => {
  test("one changed word breaks the signature", async () => {
    const tampered = issueContext.body.replace("approved it with a YubiKey touch", "approved it with a quick glance");
    expect(tampered).not.toBe(issueContext.body);

    const report = await verify(tampered, issueContext);

    expect(report.outcome).toBe("invalid");
    expect(statuses(report)).toMatchObject({ signature: "fail", subkey: "fail", repo: "pass", kind: "pass", title: "pass" });
    expect(report.checks.find((item) => item.id === "signature")?.detail).toContain("changed after signing");
  });

  test("a rewritten repo header fails both the signature and the repository check", async () => {
    const forged = issueContext.body.replace("repo: bengous/human-attest-test", "repo: someone/elsewhere");
    expect(forged).not.toBe(issueContext.body);

    const report = await verify(forged, issueContext);

    expect(report.outcome).toBe("invalid");
    expect(statuses(report)).toMatchObject({ signature: "fail", repo: "fail" });
    expect(report.checks.find((item) => item.id === "repo")?.detail).toBe(
      "Attested for someone/elsewhere, published on bengous/human-attest-test.",
    );
  });

  test("an intact block reposted on another repository fails only the place checks", async () => {
    const report = await verify(issueContext.body, { ...issueContext, repo: "someone/elsewhere" });

    expect(report.outcome).toBe("invalid");
    expect(statuses(report)).toMatchObject({ signature: "pass", subkey: "pass", repo: "fail", kind: "pass" });
  });

  test("an issue block reposted as a comment fails the kind check", async () => {
    const report = await verify(issueContext.body, { ...commentContext });

    expect(report.outcome).toBe("invalid");
    expect(statuses(report)).toMatchObject({ signature: "pass", kind: "fail" });
  });

  test("a retitled issue fails the title check", async () => {
    const report = await verify(issueContext.body, { ...issueContext, title: "Something else" });

    expect(report.outcome).toBe("invalid");
    expect(statuses(report)).toMatchObject({ signature: "pass", title: "fail" });
  });

  test("a repository renamed after the attestation fails the repository check and says why", async () => {
    const plain = await verify(renamedIssueContext.body, renamedIssueContext);
    const explained = await verify(renamedIssueContext.body, { ...renamedIssueContext, attestedRepoNow: "bengous/human-attest" });

    expect(plain.checks.find((item) => item.id === "repo")?.detail).toBe(
      "Attested for bengous/human-attest-test, published on bengous/human-attest.",
    );
    expect(explained.outcome).toBe("invalid");
    expect(statuses(explained)).toMatchObject({ signature: "pass", subkey: "pass", repo: "fail", kind: "pass", title: "pass" });
    expect(explained.checks.find((item) => item.id === "repo")?.detail).toContain("renamed or transferred after the attestation");
  });

  test("repository names compare without case", async () => {
    const report = await verify(issueContext.body, { ...issueContext, repo: "Bengous/Human-Attest-Test" });

    expect(report.outcome).toBe("valid");
  });
});

describe("format", () => {
  test("CRLF line endings verify like LF", async () => {
    const crlf = issueContext.body.replaceAll("\n", "\r\n");
    expect(crlf).toContain("\r\n");

    const report = await verify(crlf, issueContext);

    expect(report.outcome).toBe("valid");
  });

  test("trailing whitespace after the block is ignored", async () => {
    const report = await verify(`${issueContext.body}\n\n  \n`, issueContext);

    expect(report.outcome).toBe("valid");
  });

  test("a body without a block is absent, not an error", async () => {
    const plain = "Hello,\n\nthe build fails on arm64. Logs attached.\n";
    const report = await verify(plain, issueContext);

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
    const quoted = `${issueContext.body}\nThanks!\n`;
    const report = await verify(quoted, issueContext);

    expect(report.outcome).toBe("absent");
    if (report.outcome !== "absent") throw new Error("unreachable");
    expect(report.note).toContain("not as a block closing the body");
  });

  test("an unknown kind makes the block unreadable", () => {
    const split = splitAttested(issueContext.body.replace("kind: issue", "kind: gist"));

    expect(split.found).toBe(false);
  });

  test("the payload matches the documented layout", () => {
    expect(signedPayloadText("body  \r\nline\n\n", { repo: "o/n", kind: "issue", title: "T" })).toBe(
      "human-attestation v1\nrepo: o/n\nkind: issue\ntitle: T\n\nbody  \nline",
    );
    expect(signedPayloadText("x", { repo: "o/n", kind: "comment", title: undefined })).toBe(
      "human-attestation v1\nrepo: o/n\nkind: comment\n\nx",
    );
    expect(canonicalBody("a\r\nb \t\n\n")).toBe("a\nb");
  });
});

describe("links and API responses", () => {
  test("issue, pull request, comment and review links resolve to API URLs", () => {
    const cases = {
      "https://github.com/bengous/human-attest-test/issues/1": "https://api.github.com/repos/bengous/human-attest-test/issues/1",
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
      const parsed = parseGithubUrl(link);
      expect(parsed.ok).toBe(false);
    }
  });

  test("the context comes from the API response", () => {
    expect(renamedIssueContext).toMatchObject({
      source: "github",
      repo: "bengous/human-attest",
      attestedRepoNow: undefined,
      kind: "issue",
      title: "Attested test issue: hidden signature block and verification",
      author: "bengous",
      number: 1,
    });
    expect(contextFromApi(commentTarget, commentJson)).toMatchObject({ repo: "bengous/human-attest", kind: "comment", title: undefined, number: 1 });
    expect(contextFromApi(issueTarget, { ...issueJson, pull_request: { url: "x" } }).kind).toBe("pr");
  });

  test("an exhausted rate limit says when it resets and how to read the body instead", () => {
    const now = new Date("2026-11-02T12:00:00Z");
    const headers = new Headers({ "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(now.getTime() / 1000 + 600) });

    const message = describeHttpError(issueTarget, 403, headers, now);

    expect(message).toContain("60 requests per hour");
    expect(message).toContain("in about 10 minutes");
    expect(message).toContain("gh api repos/bengous/human-attest-test/issues/1 --jq .body");
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
