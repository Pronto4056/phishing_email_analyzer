# Verification record

Verified October 5, 2026 on Windows using Python 3.12.14 and installed Microsoft Edge. This record covers synthetic data only.

## Fresh environment result

Created an independent `.venv-repro`, installed `requirements-test.lock`, and ran from the repository root:

```powershell
.\.venv-repro\Scripts\python.exe -m pytest -q
```

Observed final output: **58 passed in 26.04s**, zero failures or skips. This includes two browser acceptance tests against the actual Waitress loopback server. Runtime dependencies are pinned in requirements.lock; the full verification environment is pinned in requirements-test.lock.

The test environment runs the source package through pytest's configured source path. No unpublished package or global environment dependency is required. Browser tests intentionally require installed Edge; other operating systems/browser channels are not separately verified.

## Covered behavior

- Plain-text, HTML-only, multipart, encoded/duplicate headers, nested attached email, and malformed MIME.
- Hand-labeled scores and rule IDs, repeat scoring, thresholds, benign mismatches, IP/IPv6/userinfo/punycode, and attachment metadata.
- Raw 5 MiB boundary, MIME part/depth boundaries, text/link limits, preview truncation, and decoded-payload enforcement using a lowered test limit.
- Real child process timeout, oversized output, nonzero exit, and invalid JSON paths. Production cleanup terminates/reaps workers and joins pipe readers/writers.
- Protected upload/sample routes, invalid filename/type/CSRF/Origin/Host, expired tokens, busy responses, safe errors, and security headers.
- Upload processing produced no files in the inspected temporary working directory and no sensitive marker in captured application logs. Analysis with forbidden socket creation produced the expected report.
- Browser script marker stayed unset, hostile filename became text, and no email-derived image or clickable destination was created. Recorded browser requests stayed on the local app.
- JSON download matched expected report fields and excluded body preview; clearing removed report state. A failed/partial analysis did not retain an earlier rating. Mobile viewport had no horizontal overflow.
- Keyboard focus, file upload, samples, readable malformed-email errors, desktop/mobile layout, and screenshots.

These checks are targeted evidence, not a guarantee against every input. Filesystem privacy checks inspect the tested working directory and code paths; they are not a forensic audit of all operating-system/browser activity.

## Hand-labeled bundled corpus

| File | Expected rules | Actual rules | Expected/actual score | Coverage |
| --- | --- | --- | --- | --- |
| benign.eml | none | none | 0 / 0 | complete |
| suspicious.eml | SENDER-01, LINK-01 | SENDER-01, LINK-01 | 4 / 4 | complete |
| attachment.eml | ATTACH-01 | ATTACH-01 | 3 / 3 | complete |
| partial.eml | none | none | null / null | partial |

Four of four bundled fixtures matched their hand-authored labels. This small corpus does not estimate real-world accuracy or false-positive rates. A separate benign service Reply-To case intentionally produces a contextual finding.

## Independent review and fixes

Read-only reviewer found duplicate href interpretation and conflicting duplicate MIME headers could create misleading complete reports. Each issue was reproduced by a failing regression test before changing the implementation. Fixes retain the first href, mark ambiguity, and suppress the overall rating. Empty href and defective sender comparisons were fixed in the same verified pass. Additional regression checks cover non-ASCII CSRF tokens and malformed Content-Type.

## Portfolio artifacts

- [Desktop report](screenshots/desktop-report.png)
- [Mobile partial report](screenshots/mobile-report.png)
- [Synthetic account-notice JSON](sample-report.json)
- [Worked case study](../docs/case-study.md)

## Publication status

Source and synthetic evidence published to https://github.com/Pronto4056/phishing_email_analyzer. Local development branch: build/local-analyzer. No hosted deployment has occurred; the analyzer runs locally.
