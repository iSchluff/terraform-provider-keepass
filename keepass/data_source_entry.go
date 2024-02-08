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
			"matches": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"key": {
							Type:     schema.TypeString,
							Required: true,
						},
						"value": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"title": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"username": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"url": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"notes": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"attributes": {
				Type:      schema.TypeMap,
				Computed:  true,
				Sensitive: true,
				Elem:      &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func findEntry(db *gokeepasslib.Database, path string, matches []map[string]string) (*gokeepasslib.Entry, diag.Diagnostics) {
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
			// check if the item matches all matches
			// if not, continue with next item
			entryMatchesAllMatchers := true
			for _, match := range matches {
				if item.GetContent(match["key"]) != match["value"] {
					entryMatchesAllMatchers = false
					break
				}
			}

			if entryMatchesAllMatchers {
				entry = &item
				break
			}
		}
	}
	if entry == nil {
		return nil, diag.Errorf("entry %s in path %s not found", name, path)
	}

	return entry, diags
}

func dataSourceEntryRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	db := config.db

	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	path := d.Get("path").(string)
	matches := convertMatches(d.Get("matches"))

	entry, res := findEntry(db, path, matches)
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

func convertMatches(matchInterface interface{}) []map[string]string {
	if matchInterface != nil {
		rawMatches := matchInterface.(*schema.Set).List()
		matches := make([]map[string]string, 0, len(rawMatches))
		for _, v := range rawMatches {
			matchAsInterface := v.(map[string]interface{})
			match := make(map[string]string)
			for k, v := range matchAsInterface {
				match[k] = v.(string)
			}
			matches = append(matches, match)
		}
		return matches
	} else {
		return make([]map[string]string, 0)
	}
}
