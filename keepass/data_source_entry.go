package keepass

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/tobischo/gokeepasslib/v3"
)

func dataSourceEntry() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceEntryRead,
		Schema: map[string]*schema.Schema{
			"path": {
				Type:     schema.TypeString,
				Required: true,
			},
			"title": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"password": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"notes": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"attributes": {
				Type:     schema.TypeMap,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func findEntry(db *gokeepasslib.Database, path string) (*gokeepasslib.Entry, diag.Diagnostics) {
	var diags diag.Diagnostics
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return nil, diag.Errorf("entry path '%s' does not contain any slashes", path)
	}

	// find group in root
	name := parts[0]
	var group *gokeepasslib.Group
	for _, item := range db.Content.Root.Groups {
		if item.Name == name {
			group = &item
			break
		}
	}
	if group == nil {
		diags = append(diags, diag.Errorf("group %s in path %s not found", name, path)...)
		return nil, diags
	}

	// find group in subgroups
	for i := 1; i < len(parts)-1; i++ {
		name = parts[i]
		for _, item := range group.Groups {
			if item.Name == name {
				group = &item
				break
			}
		}
		if group == nil {
			return nil, diag.Errorf("group %s in path %s not found", name, path)
		}
	}

	// find entry in group
	name = parts[len(parts)-1]
	var entry *gokeepasslib.Entry
	for _, item := range group.Entries {
		if item.GetTitle() == name {
			entry = &item
			break
		}
	}
	if entry == nil {
		return nil, diag.Errorf("entry %s in path %s not found", name, path)
	}

	return entry, diags
}

func dataSourceEntryRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	db := m.(*gokeepasslib.Database)

	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	path := d.Get("path").(string)
	entry, res := findEntry(db, path)
	diags = append(diags, res...)
	if diags.HasError() {
		return diags
	}

	attributes := make(map[string]interface{})
	for _, v := range entry.Values {
		switch v.Key {
		case "Title":
			d.Set("title", v.Value.Content)
		case "UserName":
			d.Set("username", v.Value.Content)
		case "Password":
			d.Set("password", v.Value.Content)
		case "URL":
			d.Set("url", v.Value.Content)
		case "Notes":
			d.Set("notes", v.Value.Content)
		default:
			attributes[v.Key] = v.Value.Content
		}
	}
	if err := d.Set("attributes", attributes); err != nil {
		diags = append(diags, diag.FromErr(err)...)
		return diags
	}
	d.SetId(path)

	return diags
}
