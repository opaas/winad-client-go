package client

import (
	"crypto/tls"
	"fmt"
	"github.com/opaas/winad-client-go/helper"
	"regexp"
	"strings"

	//"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v3"
)

// API is the basic struct which should implement the interface
type Client struct {
	client  *ldapconn
	Config  *ADConfig
	ADUser  ADUserService
	ADGroup ADGroupService
	ADOU    ADOUService
}

type ADObject struct {
	dn         string
	attributes map[string][]string
}

type ADConfig struct {
	host     string
	port     int
	domain   string
	useTLS   bool
	insecure bool
	user     string
	password string
	conn     ldap.Conn
}

type ldapconn struct {
	domain string
	conn   ldap.Conn
}

func NewClient(host, user, password, domain string, port int, usetls bool) (*Client, error) {

	conf := NewConfig(host, user, password, domain, port, usetls)

	c := &Client{Config: conf}
	c.ADUser = &ADUserServiceOp{client: c}
	c.ADGroup = &ADGroupServiceOp{client: c}
	c.ADOU = &ADOUServiceOp{client: c}
	return c, nil
}

// connects to an Active Directory server

func (c *Client) connect(host, username, password, domain string, port int, usetls bool) (*Client, error) {
	log.Infof("Connecting to %s:%d.", host, port)

	ldapconn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Infof(helper.FAILED_AD_CONNECT, host, port)
		return nil, fmt.Errorf("connect - failed to connect: %s", err)
	}

	log.Infof("Checking if tls connection is enabled %s", usetls)

	//Note - Please provide the fqdn here ..
	ldapConfig := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	log.Info("Configuring client to use secure connection.")
	ldapconn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", host, 636), ldapConfig)
	if err != nil {
		return nil, fmt.Errorf("connect - failed to use secure connection: %s", err)
	}

	user := username
	if ok, e := regexp.MatchString(`.*,ou=.*`, username); e != nil || !ok {
		user = fmt.Sprintf("%s@%s", user, domain)
	}

	log.Infof("Authenticating user %s.", user)
	if err = ldapconn.Bind(user, password); err != nil {
		ldapconn.Close()
		return nil, fmt.Errorf("connect - authentication failed: %s", err)
	}

	log.Infof("Connected successfully to %s:%d.", host, port)
	return c, err
}

func (c *Client) getDomainDN(domain string) string {
	tmp := strings.Split(domain, ".")
	return strings.ToLower(fmt.Sprintf("dc=%s", strings.Join(tmp, ",dc=")))
}

// Everything in AD is an ADObject

func (c *Client) searchObject(filter, baseDN string, attributes []string) ([]*ADObject, error) {
	log.Infof("Searching for objects in %s with filter %s", baseDN, filter)

	if len(attributes) == 0 {
		attributes = []string{"*"}
	}

	request := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	result, err := c.client.conn.Search(request)
	if err != nil {
		if err, ok := err.(*ldap.Error); ok {
			if err.ResultCode == 32 {
				log.Infof("No object found with filter %s", filter)
				return nil, nil
			}
		}

		return nil, fmt.Errorf("searchObject - failed to search for object (%s): %s, %s, %s, %s",
			filter, err, request.BaseDN, request.Filter, request.Attributes)
	}

	// nothing returned
	if result == nil {
		return nil, nil
	}

	objects := make([]*ADObject, len(result.Entries))
	for i, entry := range result.Entries {
		objects[i] = &ADObject{
			dn:         entry.DN,
			attributes: helper.DecodeADAttributes(entry.Attributes),
		}
	}

	return objects, nil
}

// Get returns ad object with distinguished name dn
func (c *Client) getObject(dn string, attributes []string) (*ADObject, error) {
	log.Infof("Trying to get object %s", dn)

	objects, err := c.searchObject("(objectclass=*)", dn, attributes)
	if err != nil {
		return nil, fmt.Errorf("getObject - failed to get object %s: %s", dn, err)
	}

	if len(objects) == 0 {
		return nil, nil
	}

	if len(objects) > 1 {
		return nil, fmt.Errorf("getObject - more than one object with the same dn found")
	}

	return objects[0], nil
}

// Create create a ad object
func (c *Client) createObject(dn string, classes []string, attributes map[string][]string) error {
	log.Infof("Creating object %s (class: %s)", dn, strings.Join(classes, ","))

	tmp, err := c.getObject(dn, nil)
	if err != nil {
		return fmt.Errorf("createObject - talking to active directory failed: %s", err)
	}

	// there is already an object with the same dn
	if tmp != nil {
		return fmt.Errorf("createObject - object %s already exists", dn)
	}

	// create ad add request
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", classes)

	for key, value := range attributes {
		req.Attribute(key, value)
	}

	// add to ad
	if err := c.client.conn.Add(req); err != nil {
		return fmt.Errorf("createObject - failed to create object %s: %s", dn, err)
	}

	log.Info("Object created")
	return nil
}

// Delete deletes a ad object
func (c *Client) deleteObject(dn string) error {
	log.Infof("Removing object %s", dn)

	tmp, err := c.getObject(dn, nil)
	if err != nil {
		return fmt.Errorf("deleteComputer - talking to active directory failed: %s", err)
	}

	if tmp == nil {
		log.Info("Object is already deleted")
		return nil
	}

	// create ad delete request
	req := ldap.NewDelRequest(dn, nil)

	// delete object from ad
	if err := c.client.conn.Del(req); err != nil {
		return fmt.Errorf("deleteObject - failed to delete object %s: %s", dn, err)
	}

	log.Info("Object removed")
	return nil
}

// Update updates a ad object
func (c *Client) updateObject(dn string, classes []string, added, changed, removed map[string][]string) error {
	log.Infof("Updating object %s", dn)

	tmp, err := c.getObject(dn, nil)
	if err != nil {
		return fmt.Errorf("updateObject - talking to active directory failed: %s", err)
	}

	if tmp == nil {
		return fmt.Errorf("updateObject - object %s does not exist", dn)
	}

	req := ldap.NewModifyRequest(dn, nil)

	if classes != nil {
		req.Replace("objectClass", classes)
	}

	for key, value := range added {
		req.Add(key, value)
	}

	for key, value := range changed {
		req.Replace(key, value)
	}

	for key, value := range removed {
		req.Delete(key, value)
	}

	if err := c.client.conn.Modify(req); err != nil {
		return fmt.Errorf("updateObject - failed to update %s: %s", dn, err)
	}

	log.Info("Object updated")
	return nil
}

func NewConfig(host, username, password, domain string, port int, usetls bool) *ADConfig {
	c := ADConfig{}
	c.domain = domain
	c.host = host
	c.password = password
	c.user = username
	c.port = port
	c.useTLS = usetls
	return &c
}
