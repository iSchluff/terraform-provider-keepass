package keepass

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/tobischo/gokeepasslib/v3"
)

type Config struct {
	db         *gokeepasslib.Database
	dbPath     string
	dbPassword string
	dbKey      string
	mutex      sync.Mutex
}

func NewConfig(ctx context.Context, dbPath, dbPassword, dbKey string) (*Config, diag.Diagnostics) {
	db, diags := LoadDatabase(ctx, dbPath, dbPassword, dbKey)

	if diags.HasError() {
		return nil, diags
	}

	config := &Config{
		db:         db,
		dbPath:     dbPath,
		dbPassword: dbPassword,
		dbKey:      dbKey,
	}

	return config, diags
}

func SetupDatabaseWatcher(ctx context.Context, c *Config) diag.Diagnostics {
	var diags diag.Diagnostics

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		diags = append(diags, diag.FromErr(err)...)
		return diags
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				tflog.Info(ctx, "event: "+event.Op.String()+" @ "+event.Name)
				if event.Name == c.dbPath {
					c.ReloadDatabase()
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				tflog.Error(ctx, "error on watching keepass db: "+err.Error())
			}
		}
	}()

	// add keepass database to watcher
	err = watcher.Add(filepath.Dir(c.dbPath)) // watch dir of keepass db
	if err != nil {
		diags = append(diags, diag.FromErr(err)...)
		return diags
	}

	return diags
}

func LoadDatabase(ctx context.Context, database, password, key string) (*gokeepasslib.Database, diag.Diagnostics) {
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

func (c *Config) ReloadDatabase() diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Info(context.Background(), "Reloading database")

	db, diags := LoadDatabase(context.Background(), c.dbPath, c.dbPassword, c.dbKey)
	if diags.HasError() {
		return diags
	}

	c.db = db
	return diags
}

func (c *Config) SaveDatabase(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	// Prepare the database for writing
	c.db.LockProtectedEntries()
	defer c.db.UnlockProtectedEntries()

	// Create a temporary file to save the database
	file, err := os.CreateTemp(filepath.Dir(c.dbPath), "terraform-provider-keepass-")
	if err != nil {
		tflog.Error(ctx, "Error while creating temp file for database")
		diags = append(diags, diag.FromErr(err)...)
		return diags
	}

	// Save the database to the file
	err = gokeepasslib.NewEncoder(file).Encode(c.db)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Error while saving database to %s", file.Name()))
		diags = append(diags, diag.FromErr(err)...)
		return diags
	}
	file.Close()

	// Move the file to the original database path
	err = os.Rename(file.Name(), c.dbPath)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Error while moving temp file to %s", err.Error()))
		diags = append(diags, diag.FromErr(err)...)
		os.Remove(file.Name())
		return diags
	}

	return diags
}
