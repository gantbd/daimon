# Operating rigor

- Work requests, profiles, tools, results, refusals, and evidence are closed and
  versioned.
- Provider adapters receive prepared bounded requests; they cannot expand authority
  or refresh context implicitly.
- Identity, lease evidence, authority, context visibility, and tool permission are
  independently validated.
- Time, randomness, provider identity, and receipts are explicit inputs.
- Token counts, timeouts, and process status are observations, not completion truth.
- Retry belongs to Chronos/Moira; Daimon never silently redispatches uncertain work.
- Output is a proposal until the owning engine publishes it.
- Diagnostics redact prompts, secrets, tool arguments, and generated content unless
  an explicitly authorized evidence profile says otherwise.
- Test doubles are labeled test-only and do not establish provider behavior.

