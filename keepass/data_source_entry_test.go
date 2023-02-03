package keepass

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceIntegerBasic(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testKeepassEntryBasic,
				Check: resource.ComposeTestCheckFunc(
					testAccDataSourceKeepassEntryBasic("data.keepass_entry.entry_1"),
				),
			},
		},
	})
}

func testAccDataSourceKeepassEntryBasic(id string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[id]
		if !ok {
			return fmt.Errorf("Not found: %s", id)
		}
		if rs.Primary.Attributes["title"] != "secret" {
			return fmt.Errorf("invalid title: expected 'secret', got '%s'", rs.Primary.Attributes["title"])
		}
		if rs.Primary.Attributes["username"] != "foo" {
			return fmt.Errorf("invalid username: expected 'foo', got '%s'", rs.Primary.Attributes["username"])
		}
		if rs.Primary.Attributes["password"] != "bar" {
			return fmt.Errorf("invalid password: expected 'bar', got '%s'", rs.Primary.Attributes["password"])
		}
		if rs.Primary.Attributes["url"] != "https://test.com" {
			return fmt.Errorf("invalid url: expected 'https://test.com', got '%s'", rs.Primary.Attributes["url"])
		}
		if rs.Primary.Attributes["notes"] != "some notes" {
			return fmt.Errorf("invalid notes: expected 'some notes', got '%s'", rs.Primary.Attributes["notes"])
		}
		if rs.Primary.Attributes["path"] != "Root/child1/child2/secret" {
			return fmt.Errorf("invalid path: expected 'Root/child1/child2/secret', got '%s'", rs.Primary.Attributes["path"])
		}
		if rs.Primary.Attributes["attributes.custom_attribute"] != "custom_value" {
			return fmt.Errorf("invalid custom_attribute: expected 'custom_value', got '%s'", rs.Primary.Attributes["attributes.custom_attribute"])
		}
		return nil
	}
}

const (
	testKeepassEntryBasic = `
data "keepass_entry" "entry_1" {
   path  = "Root/child1/child2/secret"
}
`
)
