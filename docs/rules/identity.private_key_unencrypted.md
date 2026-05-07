# identity.private_key_unencrypted

Flags committed PEM private key files that appear to be unencrypted.

## Why It Matters

Private keys in a repository can enable impersonation or unauthorized access.
Unencrypted key material should not be committed.

## Review

Bad:

```text
unencrypted PEM private key header
```

Good:

```text
Store private keys in a secret manager, or use encrypted local key files.
```

## Framework Note

Rotate any real exposed key. The scanner reports only file and line metadata,
not key body content.
