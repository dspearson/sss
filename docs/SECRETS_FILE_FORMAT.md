# Secrets File Format

The `.secrets` file format allows you to define reusable secret values that can be interpolated into your encrypted files using the `⊲{key}` or `<{key}` syntax.

## Basic Format

### Single-Line Values

The simplest format uses a `key: value` syntax, where the value extends to the end of the line:

```
database_password: my-secret-password-123
api_key: sk-1234567890abcdef
username: admin
```

**Key formats supported:**
- Unquoted: `my_key: value`
- Double-quoted: `"my key": value`
- Single-quoted: `'my key': value`

### Comments and Empty Lines

Lines starting with `#` are treated as comments and empty lines are ignored:

```
# Database credentials
database_password: my-secret-password-123

# API keys
api_key: sk-1234567890abcdef
```

## Multi-Line Values

For values that span multiple lines (such as SSH keys, certificates, JSON configurations, or database connection strings), use the YAML-style pipe (`|`) indicator:

### Syntax

```
key: |
  line 1
  line 2
  line 3
```

The multi-line value:
1. Starts with `key: |` on its own line
2. Following lines must be indented (any consistent indentation works)
3. Ends when a line is dedented back to or beyond the base level
4. Empty lines within the value are preserved
5. Relative indentation is preserved

### SSH Private Key Example

```
ssh_private_key: |
  -----BEGIN OPENSSH PRIVATE KEY-----
  b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
  QyNTUxOQAAACBqNGw0YXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZgAAAJgM8uEQxFqA
  AAAAJgM8uE
  -----END OPENSSH PRIVATE KEY-----
```

### Database Connection String Example

```
postgres_connection: |
  host=localhost
  port=5432
  dbname=myapp
  user=dbuser
  password=secret123
  sslmode=require
```

### JSON Configuration Example

```
aws_config: |
  {
    "region": "us-west-2",
    "credentials": {
      "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
      "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    },
    "endpoint": "https://s3.amazonaws.com"
  }
```

### Certificate Example

```
tls_certificate: |
  -----BEGIN CERTIFICATE-----
  MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKuNMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
  BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
  aWRnaXRzIFB0eSBMdGQwHhcNMTcwODI4MTUwMzMxWhcNMTgwODI4MTUwMzMxWjBF
  -----END CERTIFICATE-----
```

## Mixed Format Example

You can mix single-line and multi-line values in the same file:

```
# Single-line secrets
api_key: sk-1234567890abcdef
username: admin
environment: production

# Multi-line secrets
ssh_key: |
  -----BEGIN OPENSSH PRIVATE KEY-----
  b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=
  -----END OPENSSH PRIVATE KEY-----

database_config: |
  host=db.example.com
  port=5432
  dbname=production
  user=app_user

# More single-line secrets
smtp_host: smtp.example.com
smtp_port: 587
```

## Using Secrets in Files

Once defined in a `.secrets` file, you can reference these values in your encrypted files:

```yaml
# config.yaml
database:
  connection_string: ⊲{postgres_connection}

api:
  key: ⊲{api_key}

ssh:
  private_key: ⊲{ssh_private_key}
```

When you run `sss render config.yaml`, the markers will be replaced with the actual secret values from your `.secrets` file.

## Indentation Rules

### Base Indentation

The first non-empty line after the `|` indicator sets the base indentation level. All subsequent lines are dedented relative to this base:

```
my_key: |
    This has 4 spaces of indentation
    This also has 4 spaces
  This has only 2 spaces - collection stops here
```

Result: `"This has 4 spaces of indentation\nThis also has 4 spaces"`

### Relative Indentation

Indentation beyond the base level is preserved:

```
json_config: |
  {
    "nested": {
      "value": "preserved"
    }
  }
```

The nested structure's indentation is maintained in the output.

### Empty Lines

Empty lines within a multi-line value are preserved:

```
formatted_text: |
  First paragraph

  Second paragraph after blank line

  Third paragraph
```

## Edge Cases

### Empty Multi-Line Value

```
empty_value: |
```

Results in an empty string.

### Quoted Keys with Multi-Line Values

```
"key with spaces": |
  multi-line
  value
```

Both double and single quotes are supported for keys.

## Configuration

You can customize the secrets file name and suffix used by sss at both the project and global levels.

### Configuration Levels

**Configuration Precedence:**
1. Project configuration (`.sss.toml` in project root) - highest priority
2. User configuration (`~/.config/sss/settings.toml`)
3. System defaults: filename `"secrets"`, suffix `".secrets"`

### Project-Level Configuration

Add to your `.sss.toml` file:

```toml
# Use a different base filename (instead of "secrets")
secrets_filename = "passwords"

# Use a different file suffix (instead of ".secrets")
secrets_suffix = ".sealed"
```

**Example: Using `.sealed` suffix**

With `secrets_suffix = ".sealed"` in your project config, sss will look for secrets in:
1. `config.yaml.sealed` (file-specific secrets)
2. `secrets` file (fallback to centralized secrets)

**Example: Using custom filename**

With `secrets_filename = "passwords"` in your project config, sss will look for:
1. `config.yaml.secrets` (file-specific, uses default suffix)
2. `passwords` file (custom centralized secrets filename)

### Global User Configuration

Edit `~/.config/sss/settings.toml`:

```toml
# Global default for all projects
secrets_filename = "my_secrets"
secrets_suffix = ".passwords"
```

These settings apply to all sss projects unless overridden by project-specific configuration.

### File Discovery Strategy

sss uses a two-strategy lookup hierarchy:

**Strategy 1: File-specific secrets (suffix)**
- Looks for: `<filename><secrets_suffix>` in the same directory
- Example: `config.yaml.secrets` or `config.yaml.sealed`
- Takes precedence over centralized secrets

**Strategy 2: Centralized secrets (filename)**
- Searches upward from file directory to project root
- Looks for: `<secrets_filename>` file
- Example: `secrets`, `passwords`, `.secrets`

### Configuration Examples

**Use case: Sealed secrets pattern**
```toml
# .sss.toml
secrets_suffix = ".sealed"
```

Now you can create `myapp.yaml.sealed` alongside `myapp.yaml`:
```yaml
# myapp.yaml
database:
  password: ⊲{db_password}

# myapp.yaml.sealed (secrets file)
db_password: super_secret_123
```

**Use case: Centralized passwords file**
```toml
# .sss.toml
secrets_filename = "passwords"
```

All files in the project will use the `passwords` file for secrets lookup.

**Use case: Hidden secrets file**
```toml
# .sss.toml
secrets_filename = ".secrets"
```

The secrets file will be named `.secrets` (hidden on Unix-like systems).

## Best Practices

1. **Consistent indentation**: Use the same indentation (e.g., 2 or 4 spaces) throughout your file
2. **Meaningful keys**: Use descriptive key names like `ssh_private_key` instead of `key1`
3. **Organize by category**: Group related secrets with comments
4. **Security**: Never commit secrets files to version control - add them to `.gitignore`
5. **Validation**: Test your secrets file with `sss render` to ensure proper parsing
6. **Configuration**: Use project-level config for team-wide conventions, user config for personal preferences

## Backward Compatibility

The multi-line format and configuration options are fully backward compatible with existing sss projects. All existing files will continue to work without modification.
