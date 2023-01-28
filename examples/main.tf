terraform {
  required_providers {
    keepass = {
      version = "~> 0.2.0"
      source = "ischluff/keepass"
    }
  }
}

provider "keepass" {
  database = "passwords.kdbx"
  password = "test123"
}

data "keepass_entry" "test" {
  path = "Root/group/subgroup/testEntry"
}

output "username" {
  value = data.keepass_entry.test.username
}

output "password" {
  value = data.keepass_entry.test.password
}

output "custom_attr" {
  value = data.keepass_entry.test.attributes["custom"]
}
