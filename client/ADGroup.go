package client

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v3"
	"strings"
)

// User is the base implementation of ad Group  object
type ADGroup struct {
	name        string
	dn          string
	description string
}

type ADGroupRequest struct {
	group_name        string
	group_base_ou     string
	group_description string
}

type ADGroupService interface {
	getGroup(name, baseou string) (*ADGroup, error)
	createGroup(createUser ADGroupRequest) error
	deleteGroup(dn string) error
	updateGroupName(cn, baseOU, newOU string) error
}

type ADGroupServiceOp struct {
	client *Client
}

var _ ADGroupService = &ADGroupServiceOp{}

// returns User object
func (s *ADGroupServiceOp) getGroup(name, baseOU string) (*ADGroup, error) {
	log.Infof("getting group  from the ad server %s in %s", name, baseOU)

	attributes := []string{"name", "cn", "sAMAccountName", "description"}

	// filter
	filter := fmt.Sprintf("(&(objectclass=*)(cn=%s))", name)

	// trying to get user object
	ret, err := s.client.ADObject.searchObject(filter, baseOU, attributes)
	log.Infof("the filter is %s", filter)
	if err != nil {
		return nil, fmt.Errorf("getUser - failed to search %s in %s: %s", name, baseOU, err)
	}

	if len(ret) == 0 {
		return nil, nil
	}

	if len(ret) > 1 {
		return nil, fmt.Errorf("getUser - more than one user object with the same name under the same base ou found")
	}

	return &ADGroup{
		name:        ret[0].attributes["cn"][0],
		dn:          ret[0].dn,
		description: ret[0].attributes["sAMAccountName"][0],
	}, nil
}

// creates a new User object
func (s *ADGroupServiceOp) createGroup(gc ADGroupRequest) error {

	log.Infof("Creating group %s in %s along with the following username %s", gc.group_name, gc.group_base_ou)

	tmp, err := s.getGroup(gc.group_name, gc.group_base_ou)
	if err != nil {
		return fmt.Errorf("createUser - talking to active directory failed: %s", err)
	}

	// there is already a user object with the same name
	if tmp != nil {
		if tmp.name == gc.group_name && tmp.dn == fmt.Sprintf("cn=%s,%s", gc.group_name, gc.group_base_ou) {
			log.Infof("Group object %s already exists, updating description", gc.group_name)

		}

		return fmt.Errorf("createGroup - User object %s already exists under this base ou %s", gc.group_name, gc.group_base_ou)
	}

	attributes := make(map[string][]string)
	attributes["sAMAccountName"] = []string{gc.group_name}
	attributes["name"] = []string{gc.group_name}
	attributes["instanceType"] = []string{fmt.Sprintf("%d", 0x00000004)}
	attributes["groupType"] = []string{fmt.Sprintf("%d", 0x80000002)}

	//log.Infof("the password is %s", pwdencode)
	//return api.createObject(fmt.Sprintf("ou=%s,%s", name, baseOU), []string{"organizationalUnit", "top"}, attributes)
	//return api.createObject(fmt.Sprintf("CN=%s,%s",gc.name,gc.baseOU),[]string{"organizationalPerson", "person", "top", "user"},attributes)
	var group_cn = "CN=" + gc.group_name + "," + gc.group_base_ou
	log.Infof("Creating the group with the following cn %s", group_cn)
	err = s.client.ADObject.createObject(fmt.Sprintf("CN=%s,%s", gc.group_name, gc.group_base_ou), []string{"top", "group"}, attributes)
	if err != nil {
		return fmt.Errorf("create User - Failed to create the group: %s", err)
	}
	log.Infof("Successfully Created the Group with the cn [%s]", group_cn)

	return err

}

// updates the name of an existing user object
func (s *ADGroupServiceOp) updateGroupName(name, baseOU, newName string) error {
	log.Infof("Updating name of ou %s under %s.", name, baseOU)

	tmp, err := s.client.ADObject.searchObject("(objectclass=organizationalUnit)", name, nil)
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
func (s *ADGroupServiceOp) deleteGroup(dn string) error {
	log.Infof("Deleting user %s.", dn)

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
