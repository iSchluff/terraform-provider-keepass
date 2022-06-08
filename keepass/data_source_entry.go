package keepass

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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


func dataSourceEntryRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	meta := m.(*Meta)
	meta.mutex.Lock()
	defer meta.mutex.Unlock()

	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	path := d.Get("path").(string)
	entry, res := findEntry(meta.db, path)
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