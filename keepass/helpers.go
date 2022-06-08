package keepass

import (
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

func mkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

func mkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: w.NewBoolWrapper(true)},
	}
}

// finds a group in the database
func findGroup(db *gokeepasslib.Database, parts []string) (*gokeepasslib.Group, diag.Diagnostics) {
	var diags diag.Diagnostics
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
		diags = append(diags, diag.Errorf("group '%s' in path '%+v' not found", name, parts)...)
		return nil, diags
	}

	// find group in subgroups
	for i := 1; i < len(parts); i++ {
		name = parts[i]
		for _, item := range group.Groups {
			if item.Name == name {
				group = &item
				break
			}
		}
		if group == nil {
			return nil, diag.Errorf("group '%s' in path '%+v' not found", name, parts)
		}
	}

	return group, diags
}

func splitPath(path string) ([]string, diag.Diagnostics) {
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return nil, diag.Errorf("entry path '%s' does not contain any slashes", path)
	}
	if parts[0] == "" {
		parts = parts[1:]
	}
	return parts, nil
}

// finds an entry in the database
func findEntry(db *gokeepasslib.Database, path string) (*gokeepasslib.Entry, diag.Diagnostics) {
	parts, diags := splitPath(path)
	if diags.HasError() {
		return nil, diags
	}

	group, diags := findGroup(db, parts[:len(parts)-1])
	if diags.HasError() {
		return nil, diags
	}

	// find entry in group
	name := parts[len(parts)-1]
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

// removes an entry in the database
func removeEntry(db *gokeepasslib.Database, path string) diag.Diagnostics {
	parts, diags := splitPath(path)
	if diags.HasError() {
		return diags
	}

	group, _ := findGroup(db, parts[:len(parts)-1])
	// if group is missing we are done
	if group == nil {
		return nil
	}

	// find entry in group
	name := parts[len(parts)-1]
	var found bool
	for i, item := range group.Entries {
		if item.GetTitle() == name {
			found = true
			// remove entry by swapping the element and shortening the slice
			group.Entries[i] = group.Entries[len(group.Entries)-1]
			group.Entries = group.Entries[:len(group.Entries)-1]
			break
		}
	}
	if !found {
		return diag.Errorf("entry %s in path %s not found", name, path)
	}

	return nil
}

// creates an entry in the database and the group path leading up to it
func createEntry(db *gokeepasslib.Database, path string) (*gokeepasslib.Entry, diag.Diagnostics) {
	parts, diags := splitPath(path)
	if diags.HasError() {
		return nil, diags
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
	// create group
	if group == nil {
		tmp := gokeepasslib.NewGroup()
		tmp.Name = name
		db.Content.Root.Groups = append(db.Content.Root.Groups, tmp)
		group = &db.Content.Root.Groups[len(db.Content.Root.Groups)-1]
	}

	// find group in subgroups
	var next *gokeepasslib.Group
	for i := 1; i < len(parts)-1; i++ {
		name = parts[i]
		for _, item := range group.Groups {
			if item.Name == name {
				next = &item
				break
			}
		}
		if next == nil {
			tmp := gokeepasslib.NewGroup()
			tmp.Name = name
			group.Groups = append(group.Groups, tmp)
			next = &group.Groups[len(group.Groups)-1]
		}
		group = next
	}

	// check for duplicates
	name = parts[len(parts)-1]
	for _, item := range group.Entries {
		if item.GetTitle() == name {
			return nil, diag.Errorf("entry '%s' already exists at '%s'", name, path)
		}
	}

	// create entry
	tmp := gokeepasslib.NewEntry()
	tmp.Values = append(tmp.Values, mkValue("Title", name))
	group.Entries = append(group.Entries, tmp)
	entry := &group.Entries[len(group.Entries)-1]

	return entry, diags
}

func saveDB(db *gokeepasslib.Database, path string) diag.Diagnostics {
	file, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return diag.Errorf("failed to open db %w", err)
	}
	err = db.LockProtectedEntries()
	if err != nil {
		return diag.Errorf("failed to lock db %w", err)
	}
	err = gokeepasslib.NewEncoder(file).Encode(db)
	if err != nil {
		return diag.Errorf("failed to write db %w", err)
	}
	err = db.UnlockProtectedEntries()
	if err != nil {
		return diag.Errorf("failed to unlock db %w", err)
	}
	return nil
}
