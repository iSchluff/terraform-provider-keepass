---
page_title: "Provider: Keepass"
subcategory: ""
description: |-
  Terraform provider for reading secrets from a keepass database.
---

# Keepass Provider

The Keepass provider is used to read secrets from a keepass database file.

Use the navigation to the left to read about the available resources.

## Example Usage

Do not keep your database password in HCL for production environments, use Terraform environment variables.

```terraform
provider "keepass" {
  username = "passwords.kdbx"
  password = "test123"
}
```

## Schema

### Optional

- **database** (String) Path to database file
- **password** (String) Password to decrypt the database