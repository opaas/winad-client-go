package client

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v3"
)

// OU is the base implementation of ad organizational unit object
type ADOU struct {
	name        string
	dn          string
	description string
}

type ADOUService interface {
	getOU(name, baseou string) (*ADOU, error)
	createOU(name, baseOU, description string) error
	deleteOU(dn string) error
	updateOUDescription(cn, baseOU, newOU string) error
}

type ADOUServiceOp struct {
	client *Client
}

var _ ADOUService = &ADOUServiceOp{}

// returns ou object
func (s *ADOUServiceOp) getOU(name, baseOU string) (*ADOU, error) {
	log.Infof("Getting organizational unit %s in %s", name, baseOU)

	attributes := []string{"name", "ou", "description"}

	// filter
	filter := fmt.Sprintf("(&(objectclass=organizationalUnit)(ou=%s))", name)

	// trying to get ou object
	ret, err := s.client.ADObject.searchObject(filter, baseOU, attributes)
	if err != nil {
		return nil, fmt.Errorf("getOU - failed to search %s in %s: %s", name, baseOU, err)
	}

	if len(ret) == 0 {
		return nil, nil
	}

	if len(ret) > 1 {
		return nil, fmt.Errorf("getOU - more than one ou object with the same name under the same base ou found")
	}

	return &ADOU{
		name:        ret[0].attributes["ou"][0],
		dn:          ret[0].dn,
		description: ret[0].attributes["description"][0],
	}, nil
}

// creates a new ou object
func (s *ADOUServiceOp) createOU(name, baseOU, description string) error {
	log.Infof("Creating ou %s in %s", name, baseOU)

	tmp, err := s.getOU(name, baseOU)
	if err != nil {
		return fmt.Errorf("createOU - talking to active directory failed: %s", err)
	}

	// there is already an ou object with the same name
	if tmp != nil {
		if tmp.name == name && tmp.dn == fmt.Sprintf("ou=%s,%s", name, baseOU) {
			log.Infof("OU object %s already exists, updating description", name)
			return s.updateOUDescription(name, baseOU, description)
		}

		return fmt.Errorf("createOU - ou object %s already exists under this base ou %s", name, baseOU)
	}

	attributes := make(map[string][]string)
	attributes["ou"] = []string{name}
	attributes["description"] = []string{description}

	return s.client.ADObject.createObject(fmt.Sprintf("ou=%s,%s", name, baseOU), []string{"organizationalUnit", "top"}, attributes)
}

// moves an existing ou object to a new ou
func (s *ADOUServiceOp) moveOU(cn, baseOU, newOU string) error {
	log.Infof("Moving ou object %s from %s to %s.", cn, baseOU, newOU)

	tmp, err := s.getOU(cn, baseOU)
	if err != nil {
		return fmt.Errorf("moveOU - talking to active directory failed: %s", err)
	}

	if tmp == nil {
		return fmt.Errorf("moveOU - ou object %s does not exists under %s: %s", cn, baseOU, err)
	}

	// ou object is already in the target OU, nothing to do
	if tmp.dn == fmt.Sprintf("ou=%s,%s", cn, newOU) {
		log.Infof("OU object is already under the target ou")
		return nil
	}

	// specific uid of the ou
	UID := fmt.Sprintf("ou=%s", cn)

	// move ou object to new ou
	req := ldap.NewModifyDNRequest(fmt.Sprintf("ou=%s,%s", cn, baseOU), UID, true, newOU)
	if err := s.client.client.conn.ModifyDN(req); err != nil {
		return fmt.Errorf("moveOU - failed to move ou: %s", err)
	}

	log.Infof("OU moved.")
	return nil
}

// updates the description of an existing ou object
func (s *ADOUServiceOp) updateOUDescription(cn, baseOU, description string) error {
	log.Infof("Updating description of ou %s under %s", cn, baseOU)
	ou, err := s.getOU(cn, baseOU)
	if err != nil {
		return fmt.Errorf("updateOUDescription - talking to active directory failed: %s", err)
	}
	req := ldap.NewModifyRequest(ou.dn, nil)
	req.Replace("description", []string{description})
	if err := s.client.client.conn.Modify(req); err != nil {
		return fmt.Errorf("updateOUDescription - failed to update %s: %s", ou.dn, err)
	}
	return nil
}

// updates the name of an existing ou object
func (s *ADOUServiceOp) updateOUName(name, baseOU, newName string) error {
	log.Infof("Updating name of ou %s under %s.", name, baseOU)

	tmp, err := s.getOU(name, baseOU)
	if err != nil {
		return fmt.Errorf("updateOUName - talking to active directory failed: %s", err)
	}

	if tmp == nil {
		return fmt.Errorf("updateOUName - ou object %s does not exists under %s: %s", name, baseOU, err)
	}

	// specific uid of the ou
	UID := fmt.Sprintf("ou=%s", newName)

	// move ou object to new ou
	req := ldap.NewModifyDNRequest(fmt.Sprintf("ou=%s,%s", name, baseOU), UID, true, "")
	if err := s.client.client.conn.ModifyDN(req); err != nil {
		return fmt.Errorf("updateOUName - failed to move ou: %s", err)
	}

	log.Infof("OU moved.")
	return nil
}

// deletes an existing ou object.
func (s *ADOUServiceOp) deleteOU(dn string) error {
	log.Infof("Deleting ou %s.", dn)

	objects, err := s.client.ADObject.searchObject("(objectclass=organizationalUnit)", dn, nil)
	if err != nil {
		return fmt.Errorf("deleteOU - failed remove ou %s: %s", dn, err)
	}

	if len(objects) > 0 {
		if len(objects) > 1 || !strings.EqualFold(objects[0].dn, dn) {
			return fmt.Errorf("deleteOU - failed to delete ou %s because it has child items: %s", dn, objects[0].dn)
		}
	}

	return s.client.ADObject.deleteObject(dn)
}
