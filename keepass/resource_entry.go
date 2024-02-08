package keepass

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/tobischo/gokeepasslib/v3"
)

const (
	privateKeyFileName         = "id_rsa"
	keepassSSHSettingsFileName = "KeeAgent.settings"
)

func resourceEntry() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"group_uuid": {
				Type:        schema.TypeString,
				Description: "The UUID of the group to which the entry belongs",
				Required:    true,
				ForceNew:    true,
			},
			"title": {
				Type:        schema.TypeString,
				Description: "The title of the entry",
				Required:    true,
			},
			"username": {
				Type:        schema.TypeString,
				Description: "The username of the entry",
				Optional:    true,
			},
			"password": {
				Type:        schema.TypeString,
				Description: "The password of the entry",
				Optional:    true,
				Sensitive:   true,
			},
			"url": {
				Type:        schema.TypeString,
				Description: "The URL of the entry",
				Optional:    true,
			},
			"notes": {
				Type:        schema.TypeString,
				Description: "The notes of the entry",
				Optional:    true,
			},
			"ssh_key": {
				Type:        schema.TypeList,
				Description: "The SSH key of the entry",
				Optional:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"private_key": {
							Type:        schema.TypeString,
							Description: "The private key in OpenSSH format",
							Required:    true,
						},
						"ssh_agent_add_at_database_open": {
							Type:        schema.TypeBool,
							Description: "Automatically add the key to ssh-agent when the database is opened in a suitable client",
							Optional:    true,
							Default:     false,
						},
						"ssh_agent_remove_at_database_close": {
							Type:        schema.TypeBool,
							Description: "Automatically remove the key from ssh-agent when the database is closed in the client",
							Optional:    true,
							Default:     true,
						},
						"ssh_agent_use_confirm_constraint_when_adding": {
							Type:        schema.TypeBool,
							Description: "Require confirmation when using a key from ssh-agent",
							Optional:    true,
							Default:     false,
						},
						"ssh_agent_use_lifetime_constraint_when_adding": {
							Type:        schema.TypeBool,
							Description: "Automatically remove the key from ssh-agent after a specified period of time",
							Optional:    true,
							Default:     false,
						},
						"ssh_agent_lifetime_constraint_duration": {
							Type:        schema.TypeInt,
							Description: "The duration of the lifetime constraint in seconds after which the key gets removed from the ssh-agent",
							Optional:    true,
							Default:     600,
						},
					},
				},
				MaxItems: 1,
				MinItems: 0,
			},
		},

		CreateContext: createEntryContext,
		ReadContext:   readEntryContext,
		UpdateContext: updateEntryContext,
		DeleteContext: deleteEntryContext,
	}
}

func createEntryContext(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return createEntry(ctx, d, m, true, true)
}

func createEntry(ctx context.Context, d *schema.ResourceData, m interface{}, withLock bool, withReload bool) diag.Diagnostics {
	tflog.Info(ctx, "Creating entry")

	config := m.(*Config)

	if withLock {
		config.mutex.Lock()
		defer config.mutex.Unlock()
		tflog.Info(ctx, "Acquired lock")
	}

	if withReload {
		reloadDiags := config.ReloadDatabase()
		if reloadDiags.HasError() {
			return reloadDiags
		}
		tflog.Info(ctx, "Reloaded database")
	}

	var diags diag.Diagnostics

	groupUUUIDHex := d.Get("group_uuid").(string)
	entryGroup := FindGroup(groupUUUIDHex, config.db)
	if entryGroup == nil {
		diags = append(diags, diag.Errorf("group_uuid %s is not found in the database", groupUUUIDHex)...)
		return diags
	}

	entry := gokeepasslib.NewEntry()
	d.SetId(uuidEncoder(entry.UUID))

	entryGroup.Entries = append(entryGroup.Entries, entry)
	diags = append(diags, updateEntry(ctx, d, m, false, false)...)
	if diags.HasError() {
		tflog.Error(ctx, "Error updating entry")
		return diags
	}

	return readEntry(ctx, d, m, false, true)
}

func readEntryContext(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return readEntry(ctx, d, m, true, false)
}

func readEntry(ctx context.Context, d *schema.ResourceData, m interface{}, withLock bool, withReload bool) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Info(ctx, "Reading entry")

	config := m.(*Config)

	if withLock {
		config.mutex.Lock()
		defer config.mutex.Unlock()
		tflog.Info(ctx, "Acquired lock")
	}

	if withReload {
		reloadDiags := config.ReloadDatabase()
		if reloadDiags.HasError() {
			return reloadDiags
		}
		tflog.Info(ctx, "Reloaded database")
	}

	entry, group, diags := fetchEntry(ctx, d, m)
	if diags.HasError() {
		diags = append(diags, diags...)
		return diags
	}

	d.Set("group_uuid", uuidEncoder(group.UUID))
	d.Set("title", entry.GetTitle())
	d.Set("username", entry.GetContent("UserName"))
	d.Set("password", entry.GetContent("Password"))
	d.Set("url", entry.GetContent("URL"))
	d.Set("notes", entry.GetContent("Notes"))

	keeAgentSettingsBinary := getBinaryOf(config.db, entry, keepassSSHSettingsFileName)
	if keeAgentSettingsBinary != nil {
		tflog.Info(ctx, "KeeAgent settings found")
		tflog.Info(ctx, fmt.Sprintf("KeeAgent settings: %v", keeAgentSettingsBinary.Content))
		keeAgentSettings := parseKeeAgentSettings(ctx, keeAgentSettingsBinary.Content)
		if keeAgentSettings == nil {
			tflog.Error(ctx, "Error parsing KeeAgent settings")
			diags = append(diags, diag.Errorf("Error parsing KeeAgent settings")...)
			return diags
		}
		tflog.Info(ctx, fmt.Sprintf("KeeAgent settings: %v", keeAgentSettings))
		privateKeyBinary := getBinaryOf(config.db, entry, keeAgentSettings.PrivateKeyBinaryName)

		ssh_key := map[string]interface{}{}
		if privateKeyBinary != nil {
			tflog.Info(ctx, "Private key found")
			ssh_key["private_key"] = string(privateKeyBinary.Content)
		} else {
			tflog.Info(ctx, "Private key not found")
			ssh_key["private_key"] = nil
		}
		ssh_key["ssh_agent_add_at_database_open"] = keeAgentSettings.AddAtDatabaseOpen
		ssh_key["ssh_agent_remove_at_database_close"] = keeAgentSettings.RemoveAtDatabaseClose
		ssh_key["ssh_agent_use_confirm_constraint_when_adding"] = keeAgentSettings.UseConfirmConstraintWhenAdding
		ssh_key["ssh_agent_use_lifetime_constraint_when_adding"] = keeAgentSettings.UseLifetimeConstraintWhenAdding
		ssh_key["ssh_agent_lifetime_constraint_duration"] = keeAgentSettings.LifetimeConstraintDuration

		d.Set("ssh_key", []interface{}{ssh_key})
	} else {
		tflog.Info(ctx, "No KeeAgent settings found")
		d.Set("ssh_key", nil)
	}

	return diags
}

func updateEntryContext(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return updateEntry(ctx, d, m, true, true)
}

func updateEntry(ctx context.Context, d *schema.ResourceData, m interface{}, withLock bool, withReload bool) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Info(ctx, "Updating entry")

	config := m.(*Config)

	if withLock {
		config.mutex.Lock()
		defer config.mutex.Unlock()
		tflog.Info(ctx, "Acquired lock")
	}

	if withReload {
		reloadDiags := config.ReloadDatabase()
		if reloadDiags.HasError() {
			return reloadDiags
		}
		tflog.Info(ctx, "Reloaded database")
	}

	entry, _, diags := fetchEntry(ctx, d, m)
	if diags.HasError() {
		diags = append(diags, diags...)
		return diags
	}

	for keepass_key, terraform_key := range map[string]string{
		"Title":    "title",
		"UserName": "username",
		"Password": "password",
		"URL":      "url",
		"Notes":    "notes",
	} {
		if d.HasChange(terraform_key) {
			resourceValue := d.Get(terraform_key)
			entryValue := entry.Get(keepass_key)

			tflog.Info(ctx, fmt.Sprintf("Updating entry key: %s, terraform key: %x, resourceValue: %v, entryValue: %v", keepass_key, terraform_key, resourceValue, entryValue))

			if resourceValue == nil && entryValue != nil {
				rmValue(keepass_key, entry)
			} else if resourceValue != nil && entryValue == nil {
				if keepass_key == "password" {
					entry.Values = append(entry.Values, mkProtectedValue(keepass_key, resourceValue.(string)))
				} else {
					entry.Values = append(entry.Values, mkValue(keepass_key, resourceValue.(string)))
				}
			} else if resourceValue != nil && entryValue != nil {
				entryValue.Value.Content = resourceValue.(string)
			} else if resourceValue == nil && entryValue == nil {
				// no change
			}
		}
	}

	if d.HasChange("ssh_key") {
		sshKeyRaw := d.Get("ssh_key")

		if sshKeyRaw != nil && len(sshKeyRaw.([]interface{})) > 0 {
			sshKey := sshKeyRaw.([]interface{})[0].(map[string]interface{})

			settings := KeeAgentSettings{
				AddAtDatabaseOpen:               sshKey["ssh_agent_add_at_database_open"].(bool),
				RemoveAtDatabaseClose:           sshKey["ssh_agent_remove_at_database_close"].(bool),
				UseConfirmConstraintWhenAdding:  sshKey["ssh_agent_use_confirm_constraint_when_adding"].(bool),
				UseLifetimeConstraintWhenAdding: sshKey["ssh_agent_use_lifetime_constraint_when_adding"].(bool),
				LifetimeConstraintDuration:      sshKey["ssh_agent_lifetime_constraint_duration"].(int),
				PrivateKeyBinaryName:            privateKeyFileName,
			}
			keyAgentSettingsData := renderKeeAgentSettings(ctx, settings)
			keyAgentSettingBinary := findOrCreateBinaryIn(config.db, entry, keepassSSHSettingsFileName)
			keyAgentSettingBinary.Content = keyAgentSettingsData
			privateKeyBinary := findOrCreateBinaryIn(config.db, entry, privateKeyFileName)
			privateKeyBinary.Content = []byte(sshKey["private_key"].(string))
		} else {
			removeBinaryFrom(config.db, entry, keepassSSHSettingsFileName)
			removeBinaryFrom(config.db, entry, privateKeyFileName)
		}
	}

	dbDiags := m.(*Config).SaveDatabase(ctx)
	if dbDiags.HasError() {
		diags = append(dbDiags, diags...)
		return diags
	}

	return diags
}

func deleteEntryContext(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return deleteEntry(ctx, d, m, true, true)
}

func deleteEntry(ctx context.Context, d *schema.ResourceData, m interface{}, withLock bool, withReload bool) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Info(ctx, "Deleting entry")

	config := m.(*Config)

	if withLock {
		config.mutex.Lock()
		defer config.mutex.Unlock()
		tflog.Info(ctx, "Acquired lock")
	}

	if withReload {
		reloadDiags := config.ReloadDatabase()
		if reloadDiags.HasError() {
			return reloadDiags
		}
		tflog.Info(ctx, "Reloaded database")
	}

	entry, group, diags := fetchEntry(ctx, d, m)
	if diags.HasError() {
		diags = append(diags, diags...)
		return diags
	}

	rmEntry(entry, group)

	dbDiags := m.(*Config).SaveDatabase(ctx)
	if dbDiags.HasError() {
		diags = append(dbDiags, diags...)
		return diags
	}

	return diags
}
