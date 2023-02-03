package keepass

import (
	"context"
	"fmt"
	"os"

	"github.com/tobischo/gokeepasslib/v3"

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
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	database := d.Get("database").(string)
	password := d.Get("password").(string)
	key := d.Get("key").(string)

	var diags diag.Diagnostics

	if database == "" || password == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "database or password is not set",
		})
		return nil, diags
	}

	file, err := os.Open(database)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Unable to open keepass database at %s", database),
			Detail:   err.Error(),
		})

		return nil, diags
	}

	db := gokeepasslib.NewDatabase()
	if key != "" {
		db.Credentials, err = gokeepasslib.NewPasswordAndKeyCredentials(
			password,
			key,
		)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to decode keepass database with the given password and key",
				Detail:   err.Error(),
			})

			return nil, diags
		}
	} else {
		db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	}
	err = gokeepasslib.NewDecoder(file).Decode(db)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to decode keepass database with the given password",
			Detail:   err.Error(),
		})

		return nil, diags
	}
	db.UnlockProtectedEntries()

	return db, diags
}
