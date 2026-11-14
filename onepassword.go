package main

import (
	"context"
	"fmt"

	op "github.com/1password/onepassword-sdk-go"
)

// sectionID is the section that holds fields the broker adds; 1Password
// requires custom fields to live in a section.
const sectionID = "broker"

// opStore implements Store on a 1Password service account. Nothing is cached
// except the vault name -> ID mapping, resolved once at startup.
type opStore struct {
	client *op.Client
	vaults map[string]string
}

func newOPStore(ctx context.Context, token string, vaults []string) (*opStore, error) {
	client, err := op.NewClient(ctx,
		op.WithServiceAccountToken(token),
		op.WithIntegrationInfo("ssh-secret-broker", "v0.1.0"))
	if err != nil {
		return nil, err
	}
	all, err := client.Vaults().List(ctx)
	if err != nil {
		return nil, err
	}
	s := &opStore{client: client, vaults: map[string]string{}}
	for _, name := range vaults {
		for _, v := range all {
			if v.Title != name {
				continue
			}
			if _, dup := s.vaults[name]; dup {
				return nil, fmt.Errorf("vault name %q is ambiguous", name)
			}
			s.vaults[name] = v.ID
		}
		if s.vaults[name] == "" {
			return nil, fmt.Errorf("vault %q is not visible to the service account", name)
		}
	}
	return s, nil
}

func (s *opStore) vault(name string) (string, error) {
	id, ok := s.vaults[name]
	if !ok {
		return "", fmt.Errorf("unknown vault %q", name)
	}
	return id, nil
}

func (s *opStore) List(ctx context.Context, vault string) ([]Item, error) {
	vid, err := s.vault(vault)
	if err != nil {
		return nil, err
	}
	overviews, err := s.client.Items().List(ctx, vid, op.NewItemListFilterTypeVariantByState(
		&op.ItemListFilterByStateInner{Active: true}))
	if err != nil {
		return nil, err
	}
	items := make([]Item, len(overviews))
	for i, o := range overviews {
		items[i] = Item{ID: o.ID, Title: o.Title, Tags: o.Tags}
	}
	return items, nil
}

func (s *opStore) Get(ctx context.Context, vault, id string) (Item, error) {
	vid, err := s.vault(vault)
	if err != nil {
		return Item{}, err
	}
	it, err := s.client.Items().Get(ctx, vid, id)
	if err != nil {
		return Item{}, err
	}
	item := Item{ID: it.ID, Title: it.Title, Tags: it.Tags}
	for _, f := range it.Fields {
		item.Fields = append(item.Fields, Field{ID: f.ID, Title: f.Title, Value: f.Value})
	}
	return item, nil
}

func (s *opStore) SetField(ctx context.Context, vault, id, field, value string) error {
	vid, err := s.vault(vault)
	if err != nil {
		return err
	}
	it, err := s.client.Items().Get(ctx, vid, id)
	if err != nil {
		return err
	}
	// Same lookup order as read: by field ID first, then by title.
	target := -1
	for i, f := range it.Fields {
		if f.ID == field {
			target = i
			break
		}
		if f.Title == field && target < 0 {
			target = i
		}
	}
	if target >= 0 {
		it.Fields[target].Value = value
	} else {
		hasSection := false
		for _, sec := range it.Sections {
			hasSection = hasSection || sec.ID == sectionID
		}
		if !hasSection {
			it.Sections = append(it.Sections, op.ItemSection{ID: sectionID})
		}
		it.Fields = append(it.Fields, newField(field, value))
	}
	_, err = s.client.Items().Put(ctx, it) // tags are sent back unchanged
	return err
}

func (s *opStore) Create(ctx context.Context, vault, title, field, value string, tags []string) error {
	vid, err := s.vault(vault)
	if err != nil {
		return err
	}
	params := op.ItemCreateParams{
		Category: op.ItemCategoryLogin,
		VaultID:  vid,
		Title:    title,
		Tags:     tags,
		Fields:   []op.ItemField{newField(field, value)},
	}
	if params.Fields[0].SectionID != nil {
		params.Sections = []op.ItemSection{{ID: sectionID}}
	}
	_, err = s.client.Items().Create(ctx, params)
	return err
}

// newField builds a concealed field. "username" and "password" are built-in
// fields of a Login item; anything else goes into the broker's section.
func newField(name, value string) op.ItemField {
	f := op.ItemField{ID: name, Title: name, Value: value, FieldType: op.ItemFieldTypeConcealed}
	switch name {
	case "password":
	case "username":
		f.FieldType = op.ItemFieldTypeText
	default:
		sec := sectionID
		f.SectionID = &sec
	}
	return f
}
