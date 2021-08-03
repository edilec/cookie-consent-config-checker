# Cookie Consent Config Checker

`TOOL_ID=cookie-consent-config-checker`. Zero-dependency Node 22+ reporter for a declared consent policy and one complete, pre-captured fixture export. It reads local JSON only; it never drives a browser, loads a page, fetches a script, or changes consent settings. It checks technical configuration and the exported event order, **not legal compliance or the truth of a capture**. Consult qualified counsel for jurisdiction-specific obligations.

```sh
node bin/cookie-consent-config-checker.mjs --root examples/pass --policy policy.json --capture capture.json
node bin/cookie-consent-config-checker.mjs --root examples/fail --policy policy.json --capture capture.json
npm run check
```

The examples exit `0` and `1`. `--help` prints usage; `--human` adds a fixed stderr summary. The library exports `TOOL_ID`, `LIMITS`, `RULE_SEVERITY`, and `evaluateConsent(policy,capture,{now})` for an injected monotonic clock.

## Input contract

Both documents use `schemaVersion:"1"` and `complete:true`. The policy has nonempty `categories` and `scripts`. A category is `{id,required,defaultGranted}`; a script is `{id,category}`. IDs are lowercase ASCII letters, digits, or hyphens, start with a letter, and have at most 64 UTF-16 units. Every script category must exist. An optional (`required:false`) category defaulting to granted, or a required category defaulting to denied, fails this technical policy. The capture repeats the category and script configuration and has ordered `events`. Its `complete:true` asserts that this configuration and event list are complete for the fixture.

Events are `{type:"grant",category}`, `{type:"revoke",category}`, or `{type:"load",script}`. Array order is the captured order. The checker starts from each default, applies grant/revoke events, and fails if an optional mapped script loads while its category is not granted. A captured configuration change fails before event evaluation; an unknown event reference is incomplete. Duplicate category or script IDs, absent completeness assertions, malformed event records, or partial exports never pass. The tool does not authenticate event chronology or infer whether an absent script would have loaded later.

## Reports and limits

Stdout is one deterministic catalog-v1 JSON report. Findings use fixed `@policy` and `@capture` source roles with JSON pointers into the exact named files; IDs, raw event values, host paths, and document contents are never echoed. Findings sort by `(file,pointer,ruleId)` in UTF-16 code-unit order. `summary.checked` counts declared scripts plus valid processed events. Invalid CLI options have empty stdout, a fixed stderr diagnostic, and exit `2`; unreadable, invalid UTF-8, malformed, or over-limit input produces an `incomplete` JSON report and exit `2`. A completed technical violation exits `1`; a completed clean check exits `0`.

| Rule | Severity | Meaning |
| --- | --- | --- |
| `input-unreadable`, `input-invalid`, `export-incomplete`, `byte-limit`, `record-limit`, `depth-limit`, `time-limit` | warning | Evidence cannot be fully evaluated |
| `category-duplicate`, `script-duplicate`, `event-invalid` | warning | Identity or event evidence is ambiguous |
| `category-mismatch`, `mapping-mismatch`, `optional-default-granted`, `required-default-denied`, `script-before-consent` | error | Complete evidence conflicts with the technical policy |

Limits: 262,144 policy bytes, 1,048,576 capture bytes, 100 categories, 1,000 scripts, 10,000 events, JSON depth 16 (root at depth 0), and 5,000 ms evaluation time. Exactly N is allowed; N+1 is incomplete. Every input file's real path must remain inside the real `--root`; the CLI never writes. The direct library consumes caller-supplied objects and trusts their provenance.
