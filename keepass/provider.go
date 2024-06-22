package keepass

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Keepass Provider
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"database": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KEEPASS_DATABASE", nil),
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KEEPASS_PASSWORD", nil),
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KEEPASS_KEY", nil),
			},
		},
		DataSourcesMap: map[string]*schema.Resource{
			"keepass_entry": dataSourceEntry(),
		},
		ResourcesMap: map[string]*schema.Resource{
			"keepass_entry": resourceEntry(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	dbPath := d.Get("database").(string)
	dbPassword := d.Get("password").(string)
	dbKey := d.Get("key").(string)

	return NewConfig(ctx, dbPath, dbPassword, dbKey)
}
