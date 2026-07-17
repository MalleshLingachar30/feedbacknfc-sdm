# @feedbacknfc/sdm

Shared NTAG 424 DNA SDM verification package for FeedbackNFC products.

This package owns:

- AES-CMAC verification
- tag-key derivation from versioned master keys
- encrypted PICC data parsing
- development tap fixtures

Apps must consume this package instead of carrying local SDM verifier copies.
That keeps key rotation and replay-sensitive verification logic in one audit
surface.

## Environment

Runtime key lookup uses versioned environment variables:

```bash
SDM_MASTER_KEY_V1=
SDM_MASTER_KEY_V2=
SDM_MASTER_KEY_V3=
```

Non-production runtime falls back to deterministic development fixture keys for
tests and local tap simulation. Production does not.

