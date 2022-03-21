---
page_title: "entry Data Source - terraform-provider-keepass"
subcategory: ""
description: |-
  The entry data source allows you to retrieve information from a keepass entry.
---

# Data Source `entry`

The entry data source allows you to retrieve information from a keepass entry.

## Example Usage

```terraform
data "keepass_entry" "foo" {
  path = "Root/mygroup/myentry"
}

```

## Attributes Reference

The following attributes must be specified.

- `path` - Slash separated path to the database entry. The path names are matched to the group/entry title attributes.


The following attributes are exported.

- `title` - The entry title string
- `username` - The entry username string
- `password` - The entry password string
- `url` - The entry url string
- `notes` - The entry notes string
- `attributes` - A map of addtitional string attributes