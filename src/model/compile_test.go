package model

import (
	"testing"

	"github.com/davecgh/go-spew/spew"

	"gopkg.in/yaml.v2"
)

var data = `
Servers: 
  alpha.node.com:
    - Database Admin
  beta.node.com:
    - Database Admin
    - Mail Admin
Actions:
  Database Admin:
    User: mysql
    Expire: 3d
    Push: true
    Options: no-pty
  Mail Admin:
    User: postmaster
    Expire: 3d
    Push: true
Roles:
  MasterAdmin:
    "*.node.com":
      - Database Admin
      - Mail Admin
  Database Admin:
    "alpha.node.com":
      - Database Admin
Users:
  Johann:
    Expire: 1Y
    Roles: [MasterAdmin]
  Kyrill:
    Expire: 1Y
    Roles: [Database Admin]

`

func TestYAML(t *testing.T) {
	tvar := SystemACL{}

	err := yaml.Unmarshal([]byte(data), &tvar)
	if err != nil {
		t.Fatalf("error unmarshal: %v", err)
	}
	warnings, rows, err := tvar.toRows()
	if err != nil {
		t.Fatalf("Error compile: %s", err)
	}
	_ = warnings
	_ = rows
	spew.Dump(rows.split())
}

// ToDo:
//  - toRows config into key-lines => model.rows

// ToDo: KeyList.
//  - User.LastAuth: If present, apply expiration to it.
//  - Keys can carry expiration-date. KeyNotAfter.
//    - Mix Options and AuthorizedKeys
//  - Separate keylines per host.
//  - Sign keylines.
//  - Distribute keylines over directory structure.
//    - Remove non-present entries.

// Model ->
