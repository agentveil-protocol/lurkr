# identity.private_key_unencrypted

Flags committed PEM private key files that appear to be unencrypted.

## Why It Matters

Private keys in a repository can enable impersonation or unauthorized access.
Unencrypted key material should not be committed.

## Review

Bad:

```text
keys/server.pem
-----BEGIN PRIVATE KEY-----
[unencrypted key body]
-----END PRIVATE KEY-----
```

Good:

```bash
# Encrypt at rest:
openssl rsa -in server.pem -aes256 -out server.encrypted.pem

# Or move to secret manager:
aws ssm put-parameter --name /service/private-key --type SecureString --value "$(cat server.pem)"
rm server.pem
```

## Framework Note

Rotate any real exposed key. The scanner reports only file and line metadata,
not key body content.
