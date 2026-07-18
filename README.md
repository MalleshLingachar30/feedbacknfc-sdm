# @feedbacknfc/sdm

Shared NTAG 424 DNA SDM verification package for FeedbackNFC products.

This package owns:

- AES-CMAC verification
- tag-key derivation from versioned master keys
- encrypted PICC data parsing
- counter freshness checks for replay protection
- development tap fixtures

Apps must consume this package instead of carrying local SDM verifier copies.
That keeps key rotation and replay-sensitive verification logic in one audit
surface.

## Consumer upgrades

Current consumers pin this package to an exact git commit. Before the PlantSure
pilot, switch to signed version tags such as `v0.1.0` or add Dependabot rules in
each consumer repo so SDM security fixes produce an explicit upgrade signal.

## Replay protection

Use `verifySdmCounter` after loading the sticker's persisted last-seen counter.
It rejects any tap whose counter is less than or equal to the stored value.
Keep the consuming app's database update atomic; this package defines the shared
counter rule, and the database write remains the race-safety guard.

## Environment

Runtime key lookup uses versioned environment variables:

```bash
SDM_MASTER_KEY_V1=
SDM_MASTER_KEY_V2=
SDM_MASTER_KEY_V3=
```

Non-production runtime falls back to deterministic development fixture keys for
tests and local tap simulation. Production does not.
