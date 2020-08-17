package helper

import (
	"encoding/base64"
	"fmt"
	"gopkg.in/ldap.v3"
)

func DecodeADAttributes(attributes []*ldap.EntryAttribute) map[string][]string {
	attr := make(map[string][]string)

	for _, e := range attributes {
		attr[e.Name] = e.Values
	}

	return attr
}

type SID struct {
	RevisionLevel     int
	SubAuthorityCount int
	Authority         int
	SubAuthorities    []int
	RelativeID        *int
}

func Siddecode(input string) (string, int) {
	bsid, _ := base64.StdEncoding.DecodeString(input)

	sid := Decode(bsid)
	fmt.Println(sid.Authority)

	fmt.Println(sid)
	return sid.String(), sid.RID()
}

func (sid SID) String() string {
	s := fmt.Sprintf("S-%d-%d", sid.RevisionLevel, sid.Authority)
	for _, v := range sid.SubAuthorities {
		s += fmt.Sprintf("-%d", v)
	}
	return s
}

func (sid SID) RID() int {
	l := len(sid.SubAuthorities)
	return sid.SubAuthorities[l-1]
}

func Decode(b []byte) SID {

	var sid SID

	sid.RevisionLevel = int(b[0])
	sid.SubAuthorityCount = int(b[1]) & 0xFF

	for i := 2; i <= 7; i++ {
		sid.Authority = sid.Authority | int(b[i])<<(8*(5-(i-2)))
	}

	var offset = 8
	var size = 4
	for i := 0; i < sid.SubAuthorityCount; i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(b[offset+k])&0xFF)<<(8*k)
		}
		sid.SubAuthorities = append(sid.SubAuthorities, subAuthority)
		offset += size
	}

	return sid
}
