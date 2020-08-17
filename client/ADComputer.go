package client

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v3"
)

// Computer is the base implementation of ad computer object
type ADComputer struct {
	name        string
	dn          string
	description string
}

type ADComputerRequest struct {
	group_name        string
	group_base_ou     string
	group_description string
}

type ADComputerService interface {
	getComputer(name string) (*ADComputer, error)
	createComputer(cn, ou, description string) error
}

type ADComputerServiceOp struct {
	client *Client
}

var _ ADComputerService = &ADComputerServiceOp{}

// returns computer object
func (s *ADComputerServiceOp) getComputer(name string) (*ADComputer, error) {
	log.Infof("Searching ad computer %s", name)

	domain := s.client.getDomainDN()
	attributes := []string{"cn", "description"}

	// ldap filter
	filter := fmt.Sprintf("(&(objectclass=computer)(name=%s))", name)

	// trying to get ou object
	ret, err := s.client.ADObject.searchObject(filter, domain, attributes)
	if err != nil {
		return nil, fmt.Errorf("getComputer - searching for computer object %s failed: %s", name, err)
	}

	if len(ret) == 0 {
		return nil, nil
	}

	if len(ret) > 1 {
		return nil, fmt.Errorf("getComputer - more than one computer object with the same name found")
	}

	return &ADComputer{
		name:        ret[0].attributes["cn"][0],
		dn:          ret[0].dn,
		description: ret[0].attributes["description"][0],
	}, nil
}

// creates a new computer object
func (s *ADComputerServiceOp) createComputer(cn, ou, description string) error {
	log.Infof("Creating computer object %s in %s", cn, ou)

	tmp, err := s.getComputer(cn)
	if err != nil {
		return fmt.Errorf("createComputer - talking to active directory failed: %s", err)
	}

	// there is already a computer object with the same name
	if tmp != nil {
		if tmp.name == cn && tmp.dn == fmt.Sprintf("cn=%s,%s", cn, ou) {
			log.Infof("Computer object %s already exists, updating description", cn)
			return s.updateComputerDescription(cn, ou, description)
		}

		return fmt.Errorf("createComputer - computer object %s already exists in a different ou", cn)
	}

	attributes := make(map[string][]string)
	attributes["name"] = []string{cn}
	attributes["sAMAccountName"] = []string{cn + "$"}
	attributes["userAccountControl"] = []string{"4096"}
	attributes["description"] = []string{description}

	return s.client.ADObject.createObject(fmt.Sprintf("cn=%s,%s", cn, ou), []string{"computer"}, attributes)
}

// moves an existing computer object to a new ou
func (s *ADComputerServiceOp) updateComputerOU(cn, ou, newOU string) error {
	log.Infof("Moving computer object %s from %s to %s", cn, ou, newOU)

	tmp, err := s.getComputer(cn)
	if err != nil {
		return fmt.Errorf("updateComputerOU - talking to active directory failed: %s", err)
	}

	if tmp == nil {
		return fmt.Errorf("updateComputerOU - computer object %s does not exists: %s", cn, err)
	}

	// computer object is already in the target OU, nothing to do
	if strings.EqualFold(tmp.dn, fmt.Sprintf("cn=%s,%s", cn, newOU)) {
		log.Infof("Computer object is already in the target ou")
		return nil
	}

	// specific uid of the computer
	computerUID := fmt.Sprintf("cn=%s", cn)

	// move computer object to new ou
	req := ldap.NewModifyDNRequest(fmt.Sprintf("cn=%s,%s", cn, ou), computerUID, true, newOU)
	if err := s.client.client.conn.ModifyDN(req); err != nil {
		return fmt.Errorf("updateComputerOU - failed to move computer object: %s", err)
	}

	log.Info("Object moved successfully")
	return nil
}

// updates the description of an existing computer object
func (s *ADComputerServiceOp) updateComputerDescription(cn, ou, description string) error {
	log.Infof("Updating description of computer object %s", cn)
	return s.client.ADObject.updateObject(fmt.Sprintf("cn=%s,%s", cn, ou), nil, nil, map[string][]string{
		"description": {description},
	}, nil)
}

// deletes an existing computer object.
func (s *ADComputerServiceOp) deleteComputer(cn, ou string) error {
	log.Infof("Deleting computer object %s", cn)
	return s.client.ADObject.deleteObject(fmt.Sprintf("cn=%s,%s", cn, ou))
}
