package keepass

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func FindGroup(uuid string, db *gokeepasslib.Database) *gokeepasslib.Group {
	uuidArray, error := uuidDecoder(uuid)
	if error != nil {
		return nil
	}

	for i := range db.Content.Root.Groups {
		group := &db.Content.Root.Groups[i]
		groupCadidate := FindGroupIn(uuidArray, group)
		if groupCadidate != nil {
			return groupCadidate
		}
	}

	return nil
}

func FindGroupIn(uuid [16]byte, root *gokeepasslib.Group) *gokeepasslib.Group {
	if root.UUID.Compare(uuid) {
		return root
	}

	for i := range root.Groups {
		group := &root.Groups[i]
		groupCadidate := FindGroupIn(uuid, group)
		if groupCadidate != nil {
			return groupCadidate
		}
	}

	return nil
}

func FindEntryIn(uuid string, group *gokeepasslib.Group) *gokeepasslib.Entry {
	uuidArray, error := uuidDecoder(uuid)
	if error != nil {
		return nil
	}

	for i := range group.Entries {
		entry := &group.Entries[i]
		if entry.UUID.Compare(uuidArray) {
			return entry
		}
	}

	return nil
}

func mkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

func mkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: w.NewBoolWrapper(true)},
	}
}

func rmValue(key string, entry *gokeepasslib.Entry) diag.Diagnostics {
	var diags diag.Diagnostics

	for i, v := range entry.Values {
		if v.Key == key {
			entry.Values = append(entry.Values[:i], entry.Values[i+1:]...)
			return diags
		}
	}

	diags = append(diags, diag.Errorf("key %s is not found in the entry", key)...)
	return diags
}

func rmEntry(entry *gokeepasslib.Entry, group *gokeepasslib.Group) {
	for i, e := range group.Entries {
		if e.UUID.Compare(entry.UUID) {
			group.Entries = append(group.Entries[:i], group.Entries[i+1:]...)
			return
		}
	}
}

func uuidDecoder(uuid string) (gokeepasslib.UUID, error) {
	uuidBytes, error := hex.DecodeString(uuid)
	if error != nil {
		return gokeepasslib.UUID{}, error
	}

	uuidArray := gokeepasslib.UUID{}
	copy(uuidArray[:], uuidBytes[:16])

	return uuidArray, nil
}

func uuidEncoder(uuid gokeepasslib.UUID) string {
	return hex.EncodeToString(uuid[:])
}

func fetchEntry(ctx context.Context, d *schema.ResourceData, m interface{}) (*gokeepasslib.Entry, *gokeepasslib.Group, diag.Diagnostics) {
	config := m.(*Config)

	var diags diag.Diagnostics

	tflog.Debug(ctx, "Reading entry")

	groupUUID := d.Get("group_uuid").(string)
	entryGroup := FindGroup(groupUUID, config.db)
	if entryGroup == nil {
		diags = append(diags, diag.Errorf("group_uuid %s is not found in the database", groupUUID)...)
		return nil, nil, diags
	}

	entryUUID := d.Id()
	entry := FindEntryIn(entryUUID, entryGroup)
	if entry == nil {
		diags = append(diags, diag.Errorf("entry_uuid %s is not found in the database", entryUUID)...)
		return nil, nil, diags
	}

	return entry, entryGroup, diags
}

func getBinaryOf(db *gokeepasslib.Database, entry *gokeepasslib.Entry, name string) *gokeepasslib.Binary {
	var binaryReference *gokeepasslib.BinaryReference = nil

	for _, binary := range entry.Binaries {
		if binary.Name == name {
			binaryReference = &binary
			break
		}
	}

	if binaryReference == nil {
		return nil
	}

	return db.FindBinary(binaryReference.Value.ID)
}

func removeBinaryFrom(db *gokeepasslib.Database, entry *gokeepasslib.Entry, name string) {
	for i, binary := range entry.Binaries {
		if binary.Name == name {
			entry.Binaries = append(entry.Binaries[:i], entry.Binaries[i+1:]...)
			break
		}
	}
}

func addBinaryTo(db *gokeepasslib.Database, entry *gokeepasslib.Entry, name string, data []byte) *gokeepasslib.Binary {
	binary := db.AddBinary(data)
	entry.Binaries = append(entry.Binaries, binary.CreateReference(name))

	return binary
}

func findOrCreateBinaryIn(db *gokeepasslib.Database, entry *gokeepasslib.Entry, name string) *gokeepasslib.Binary {
	binary := getBinaryOf(db, entry, name)
	if binary == nil {
		binary = addBinaryTo(db, entry, name, []byte{})
	}

	return binary
}

func renderKeeAgentSettings(ctx context.Context, settings KeeAgentSettings) []byte {
	xmlTemplate := XMLEntrySettings{
		AllowUseOfSshKey:                true,
		AddAtDatabaseOpen:               settings.AddAtDatabaseOpen,
		RemoveAtDatabaseClose:           settings.RemoveAtDatabaseClose,
		UseConfirmConstraintWhenAdding:  settings.UseConfirmConstraintWhenAdding,
		UseLifetimeConstraintWhenAdding: settings.UseLifetimeConstraintWhenAdding,
		LifetimeConstraintDuration:      settings.LifetimeConstraintDuration,
		Location: XMLLocation{
			SelectedType:             "attachment",
			AttachmentName:           settings.PrivateKeyBinaryName,
			SaveAttachmentToTempFile: false,
		},
	}

	xmlData, err := xml.MarshalIndent(xmlTemplate, "", "  ")
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("error marshalling xml: %v", err))
		return nil
	}

	xmlData = []byte(`<?xml version="1.0" encoding="UTF-16"?>` + "\n" + string(xmlData))

	tflog.Info(ctx, fmt.Sprintf("xml: %s", xmlData))

	var buffer bytes.Buffer
	writer := transform.NewWriter(&buffer, unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewEncoder())
	_, err = writer.Write(xmlData)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("error marshalling xml: %v", err))
		return nil
	}

	return buffer.Bytes()

}

// Example KeeAgent.settings:
//
// <?xml version="1.0" encoding="UTF-16"?>
// <EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
// 	<AllowUseOfSshKey>true</AllowUseOfSshKey>
// 	<AddAtDatabaseOpen>true</AddAtDatabaseOpen>
// 	<RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>
// 	<UseConfirmConstraintWhenAdding>false</UseConfirmConstraintWhenAdding>
// 	<UseLifetimeConstraintWhenAdding>false</UseLifetimeConstraintWhenAdding>
// 	<LifetimeConstraintDuration>1800</LifetimeConstraintDuration>
// 	<Location>
// 		<SelectedType>attachment</SelectedType>
// 		<AttachmentName>id_rsa</AttachmentName>
// 		<SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
// 		<FileName/>
// 	</Location>
// </EntrySettings>

// Encoding is 'utf-16-le'

type XMLEntrySettings struct {
	XMLName                         xml.Name    `xml:"EntrySettings"`
	AllowUseOfSshKey                bool        `xml:"AllowUseOfSshKey"`
	AddAtDatabaseOpen               bool        `xml:"AddAtDatabaseOpen"`
	RemoveAtDatabaseClose           bool        `xml:"RemoveAtDatabaseClose"`
	UseConfirmConstraintWhenAdding  bool        `xml:"UseConfirmConstraintWhenAdding"`
	UseLifetimeConstraintWhenAdding bool        `xml:"UseLifetimeConstraintWhenAdding"`
	LifetimeConstraintDuration      int         `xml:"LifetimeConstraintDuration"`
	Location                        XMLLocation `xml:"Location"`
}

type XMLLocation struct {
	XMLName                  xml.Name `xml:"Location"`
	SelectedType             string   `xml:"SelectedType"`
	AttachmentName           string   `xml:"AttachmentName"`
	SaveAttachmentToTempFile bool     `xml:"SaveAttachmentToTempFile"`
	FileName                 string   `xml:"FileName"`
}

type KeeAgentSettings struct {
	PrivateKeyBinaryName            string
	AddAtDatabaseOpen               bool
	RemoveAtDatabaseClose           bool
	UseConfirmConstraintWhenAdding  bool
	UseLifetimeConstraintWhenAdding bool
	LifetimeConstraintDuration      int
}

func parseKeeAgentSettings(ctx context.Context, data []byte) *KeeAgentSettings {

	utf16LEDecoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	reader := transform.NewReader(bytes.NewReader([]byte(data)), utf16LEDecoder)

	data, err := io.ReadAll(reader)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("error: %v", err))
		return nil
	}

	data = bytes.Replace(data, []byte(`encoding="UTF-16"`), []byte(`encoding="UTF-8"`), -1)

	var result XMLEntrySettings
	err = xml.Unmarshal(data, &result)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("error: %v", err))
		return nil
	}

	return &KeeAgentSettings{
		PrivateKeyBinaryName:            result.Location.AttachmentName,
		AddAtDatabaseOpen:               result.AddAtDatabaseOpen,
		RemoveAtDatabaseClose:           result.RemoveAtDatabaseClose,
		UseConfirmConstraintWhenAdding:  result.UseConfirmConstraintWhenAdding,
		UseLifetimeConstraintWhenAdding: result.UseLifetimeConstraintWhenAdding,
		LifetimeConstraintDuration:      result.LifetimeConstraintDuration,
	}
}
