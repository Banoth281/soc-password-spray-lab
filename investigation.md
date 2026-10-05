# Investigation: multi-account authentication failures

## Scope

Synthetic offline training records only. All IP addresses use documentation ranges. No accounts were accessed and no containment was performed.

## Observed evidence

- Source `198.51.100.25` fails authentication against Alice, Bob, Charlie, Diana and Erin between 10:00:00 and 10:02:00 UTC on 5 October 2026.
- The fifth distinct account triggers an alert at 10:02:00.
- Frank has a failure from the same source at 10:02:30.
- Alice has a successful login from the same source at 10:03:00.
- Grace's repeated failures from another source affect one account and do not trigger this rule.

## Assessment

The sequence warrants investigation for possible password spraying. The CSV does not show attempted passwords, user confirmation, MFA outcomes or device identity. Password reuse across targets and account compromise cannot be confirmed. No fictional follow-up findings are presented as evidence.

## Alternative explanations

A shared gateway, authentication misconfiguration or legitimate users making errors could produce this pattern. Source IP identifies a network origin in these records, not necessarily one person or device.

## Proposed triage

1. Preserve original records and the generated report.
2. Check whether the source is a known shared gateway and review available device and application context.
3. Inspect MFA, session and post-login records for Alice's successful authentication.
4. Contact the account owner through the approved verification process if required.
5. Escalate if additional evidence supports unauthorised access; perform containment only through the authorised response procedure.
6. Document evidence, uncertainty, disposition and any rule tuning.

## Disposition

Requires investigation. There is insufficient evidence to confirm compromise or close as benign. All response steps are proposals only.
