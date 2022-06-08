package keepass

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceEntry() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceEntryCreate,
		ReadContext:   dataSourceEntryRead,
		UpdateContext: resourceOrderUpdate,
		DeleteContext: resourceOrderDelete,
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
                Optional: true,
			},
			"password": {
				Type:     schema.TypeString,
                Optional: true,
			},
			"url": {
				Type:     schema.TypeString,
                Optional: true,
			},
			"notes": {
				Type:     schema.TypeString,
                Optional: true,
			},
			"attributes": {
				Type:     schema.TypeMap,
				Elem:     &schema.Schema{Type: schema.TypeString},
                Optional: true,
			},
		},
	}
}

func resourceEntryCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	meta := m.(*Meta)

    meta.mutex.Lock()
	path := d.Get("path").(string)
	entry, diags := createEntry(meta.db, path)
	if diags.HasError() {
        meta.mutex.Unlock()
		return diags
	}

	// set fields
    entry.Values = append(entry.Values, mkValue("UserName", d.Get("username").(string)))
    entry.Values = append(entry.Values, mkProtectedValue("Password", d.Get("password").(string)))
    entry.Values = append(entry.Values, mkValue("URL", d.Get("url").(string)))
    entry.Values = append(entry.Values, mkValue("Notes", d.Get("notes").(string)))
	attributes := d.Get("attributes").(map[string]interface{})
	for k, v := range attributes {
		entry.Values = append(entry.Values, mkValue(k, v.(string)))
	}

	// write file
    diags = saveDB(meta.db, meta.path)
    meta.mutex.Unlock()
    if diags.HasError() {
        return diags
    }

    // read changes
	return dataSourceEntryRead(ctx, d, m)
}

func resourceOrderUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	meta := m.(*Meta)

    meta.mutex.Lock()
	path := d.Get("path").(string)
	entry, diags := createEntry(meta.db, path)
	if diags.HasError() {
        meta.mutex.Unlock()
		return diags
	}

	// update fields
    // missing kvs in the entry are currently not handled!
    for i, v := range entry.Values {
        switch(v.Key) {
        case "UserName":
		    if d.HasChange("username") {
                entry.Values[i].Value.Content = d.Get("username").(string)
            }
		case "Password":
            if d.HasChange("password") {
                entry.Values[i].Value.Content = d.Get("password").(string)
            }
		case "URL":
			if d.HasChange("url") {
                entry.Values[i].Value.Content = d.Get("url").(string)
            }
		case "Notes":
			if d.HasChange("notes") {
                entry.Values[i].Value.Content = d.Get("notes").(string)
            }
		default:
            if val, ok := d.Get("attributes").(map[string]interface{})[v.Key]; ok {
                entry.Values[i].Value.Content = val.(string)
            }
		}
    }

	// write file
    diags = saveDB(meta.db, meta.path)
    meta.mutex.Unlock()
    if diags.HasError() {
        return diags
    }

    // read changes
	return dataSourceEntryRead(ctx, d, m)
}

func resourceOrderDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
    meta := m.(*Meta)

    meta.mutex.Lock()
    defer meta.mutex.Unlock()

    // remove entry
	path := d.Get("path").(string)
	diags := removeEntry(meta.db, path)
	if diags.HasError() {
		return diags
	}

    // write file
    diags = saveDB(meta.db, meta.path)
    if diags.HasError() {
        return diags
    }

	return nil
}
