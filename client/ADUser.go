package client

import (
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/surajsub/winad-client-go/helper"
	"golang.org/x/text/encoding/unicode"
	"strconv"
	"time"

	"gopkg.in/ldap.v3"
	"strings"
)

type ADUserRequest struct {
	firstname     string
	lastname      string
	name          string
	cn            string
	sn            string
	baseOU        string
	description   string
	email         string
	newOU         string
	newName       string
	adAccountName string // This is the SAM Account Name
	dn            string
	cdir          string
	given_name    string
	password      string
}

// User is the base implementation of ad User  object
type ADUser struct {
	name string
	dn   string
	//description string
	sn  string
	sid string
}

type ADUserService interface {
	getUser(name, baseou string) (*ADUser, error)
	createUser(createUser ADUserRequest) error
	deleteUser(dn string) error
	moveUser(cn, baseOU, newOU string) error
}

type ADUserServiceOp struct {
	client *Client
}

var _ ADUserService = &ADUserServiceOp{}

// returns User object
func (s *ADUserServiceOp) getUser(name, baseOU string) (*ADUser, error) {
	log.Infof("getting User  from the ad server %s in %s", name, baseOU)

	attributes := []string{"name", "cn", "sAMAccountName", "description", "sn", "objectSid"}
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
	log.Infof("Printing the value %v", ret[0].attributes)

	return &ADUser{
		name: ret[0].attributes["cn"][0],
		dn:   ret[0].dn,
		//description: ret[0].attributes["description"][0],
		sn:  ret[0].attributes["sn"][0],
		sid: ret[0].attributes["objectSid"][0],
	}, nil
}

// creates a new User object
func (s *ADUserServiceOp) createUser(user_create ADUserRequest) error {

	log.Infof("Creating User %s in %s along with the following username %s", user_create.name, user_create.baseOU, user_create.email)

	tmp, err := s.getUser(user_create.name, user_create.baseOU)
	if err != nil {
		return fmt.Errorf("createUser - talking to active directory failed: %s", err)
	}
	// there is already a user object with the same name
	if tmp != nil {
		if tmp.name == user_create.name && tmp.dn == fmt.Sprintf("cn=%s,%s", user_create.name, user_create.baseOU) {
			log.Infof("User object %s already exists, updating description", user_create.name)

		}

		return fmt.Errorf("createUser - User object %s already exists under this base ou %s", user_create.name, user_create.baseOU)
	}

	current := time.Now()
	var cd = current.Format("20060102")
	var fullName = fmt.Sprintf("%s %s", user_create.given_name, user_create.sn)
	log.Infof("the fullname is [%s]", fullName)
	var description = fmt.Sprintf("%s,%s/%s/%s//%s,%s%s,%s%s,%s", user_create.name, "897", "C", user_create.cdir, fullName, "CD=", cd, "RI=", "OPAASAUTO", "#CUST#")

	var principalName = fmt.Sprintf("%s@%s", user_create.name, s.client.client.domain)
	log.Infof("Printing the prinicipalName %s", principalName)
	attributes := make(map[string][]string)
	attributes["sAMAccountName"] = []string{user_create.name}
	attributes["userPrincipalName"] = []string{principalName} // FirstName+LastName @imzcloud-- Must be unique
	attributes["name"] = []string{fullName}
	attributes["givenName"] = []string{user_create.given_name}
	attributes["displayName"] = []string{fullName}
	attributes["sn"] = []string{user_create.sn} // This is the last name
	attributes["description"] = []string{description}
	attributes["userAccountControl"] = []string{fmt.Sprintf("%d", 0x0202)}
	attributes["mail"] = []string{user_create.email}
	attributes["accountExpires"] = []string{fmt.Sprintf("%d", 0x00000000)}

	var password = user_create.password
	ust := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	encoded, err := ust.NewEncoder().String(fmt.Sprintf("%q", password))
	if err != nil {
		log.Fatal(err)
	}
	var usercn = "CN=" + user_create.name + "," + user_create.baseOU
	log.Infof("Creating the user with the following cn %s", usercn)
	err = s.client.ADObject.createObject(fmt.Sprintf("CN=%s,%s", user_create.name, user_create.baseOU), []string{"organizationalPerson", "person", "top", "user"}, attributes)
	if err != nil {
		return fmt.Errorf("create User - Failed to create the user: %s", err)
	}
	log.Infof("Successfully Created the User with the cn [%s]", usercn)
	pwdencodereq := ldap.NewModifyRequest(usercn, nil)
	pwdencodereq.Replace("unicodePwd", []string{encoded})

	if err := s.client.client.conn.Modify(pwdencodereq); err != nil {
		return fmt.Errorf("failed to execute the modify password request", pwdencodereq, err)
	}

	userControlReq := ldap.NewModifyRequest(usercn, nil)
	userControlReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", 0x0200)})
	if err := s.client.client.conn.Modify(userControlReq); err != nil {
		log.Fatal("error Setting the user control", userControlReq, err)
	}

	userdata, err := s.getUser(user_create.name, user_create.baseOU)
	if err != nil {
		return fmt.Errorf("createUser - talking to active directory failed: %s", err)
	}

	//update_sid := strings.ReplaceAll(userdata.sid,"\\x","")
	log.Infof("Printing the dn [ %s] and the sid %x", userdata.dn, userdata.sid)

	data := base64.StdEncoding.EncodeToString([]byte(userdata.sid))

	log.Infof("Spitting out the base64 stuff %s", data)
	sid, rid := helper.Siddecode(data)
	log.Infof("Printing the sid %s", sid)
	log.Infof("The unique id that will be generated is [%d]", rid+1000)
	var generatedNumber = rid + 1000
	uidnumberreq := ldap.NewModifyRequest(usercn, nil)
	uidnumberreq.Replace("uidNumber", []string{strconv.Itoa(generatedNumber)})

	if err := s.client.client.conn.Modify(uidnumberreq); err != nil {
		log.Fatal("unable to update the userid that was just created", uidnumberreq, err)
	}

	return err
}

// moves an existing ou object to a new ou
func (s *ADUserServiceOp) moveUser(cn, baseOU, newOU string) error {
	log.Infof("Moving ou object %s from %s to %s.", cn, baseOU, newOU)

	tmp, err := s.getUser(cn, baseOU)
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

//

// updates the name of an existing user object
func (s *ADUserServiceOp) updateUserName(name, baseOU, newName string) error {
	log.Infof("Updating name of user %s under %s.", name, baseOU)

	tmp, err := s.getUser(name, baseOU)
	if err != nil {
		return fmt.Errorf("updateOUName - talking to active directory failed: %s", err)
	}

	if tmp == nil {
		return fmt.Errorf("updateOUName - ou object %s does not exists under %s: %s", name, baseOU, err)
	}

	// specific uid of the user
	UID := fmt.Sprintf("ou=%s", newName)

	// move ou object to new ou
	req := ldap.NewModifyDNRequest(fmt.Sprintf("ou=%s,%s", name, baseOU), UID, true, "")
	if err := s.client.client.conn.ModifyDN(req); err != nil {
		return fmt.Errorf("updateOUName - failed to move ou: %s", err)
	}

	log.Infof("user moved.")
	return nil
}

// deletes an existing ou object.
func (s *ADUserServiceOp) deleteUser(dn string) error {
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

func (s *ADUserServiceOp) addUserToGroup(userdn, groupdn string) error {

	//First look up the user from the given cn

	// Then lookup the groupdn from the given string

	groupmodifyReq := ldap.NewModifyRequest(groupdn, nil)
	groupmodifyReq.Add("member", []string{userdn})
	if err := s.client.client.conn.Modify(groupmodifyReq); err != nil {
		log.Fatal("unable to add the newly create user to the group ", groupmodifyReq, err)
	}

	log.Infof("adding user to the group")

	return nil
}
