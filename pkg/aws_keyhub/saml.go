package aws_keyhub

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"github.com/sirupsen/logrus"
	"strings"
)

func DecodeSAMLResponse(samlResponse string) []byte {
	decoded, err := base64.URLEncoding.DecodeString(samlResponse)
	if err != nil {
		logrus.Fatal("Failed to decode SAML Response from KeyHub.", err)
	}

	logrus.Debugln("Decoded SAML Response", string(decoded))
	return decoded
}

func RolesAndPrincipalsFromSamlResponse(samlResponseDecoded []byte) map[string]RolesAndPrincipals {
	var response Response
	xml.Unmarshal(samlResponseDecoded, &response)
	logrus.Debugln("Unmarshalled SAML Assertion:", response)

	var rolesAndPrincipals = make(map[string]RolesAndPrincipals)

	for _, assertion := range response.Assertion {
		for _, attributeStatement := range assertion.AttributeStatement {
			for _, attribute := range attributeStatement.Attribute {
				for _, attributeValue := range attribute.AttributeValue {

					if attribute.Name == "https://github.com/topicuskeyhub/aws-keyhub/groups" {

						var groupsMetadata GroupsMetadata
						if err := json.Unmarshal([]byte(attributeValue), &groupsMetadata); err != nil {
							logrus.Warning("Cannot unmarshal JSON nested in the SAML Assertion containing groups metadata.")
						}

						if existingItem, exists := rolesAndPrincipals[groupsMetadata.Arn]; exists {
							existingItem.Description = groupsMetadata.Description
							rolesAndPrincipals[groupsMetadata.Arn] = existingItem
						} else {
							rolesAndPrincipals[groupsMetadata.Arn] = RolesAndPrincipals{Description: groupsMetadata.Description}
						}
					}

					if attribute.Name == "https://aws.amazon.com/SAML/Attributes/Role" {
						role, principal := splitRoleAndPrincipal(attributeValue)

						if existingItem, exists := rolesAndPrincipals[attributeValue]; exists {
							existingItem.Role = role
							existingItem.Principal = principal
							rolesAndPrincipals[attributeValue] = existingItem
						} else {
							rolesAndPrincipals[attributeValue] = RolesAndPrincipals{Role: role, Principal: principal}
						}
					}
				}

			}
		}
	}

	return rolesAndPrincipals
}

func splitRoleAndPrincipal(roleAndPrincipal string) (role string, principal string) {
	for _, part := range strings.Split(roleAndPrincipal, ",") {
		if strings.Contains(part, "role") {
			role = part
		}
		if strings.Contains(part, "saml-provider") {
			principal = part
		}
	}

	return role, principal
}

type Response struct {
	XMLName   xml.Name    `xml:"Response"`
	Assertion []Assertion `xml:"Assertion"`
}

type Assertion struct {
	XMLName            xml.Name             `xml:"Assertion"`
	AttributeStatement []AttributeStatement `xml:"AttributeStatement"`
}

type AttributeStatement struct {
	XMLName   xml.Name    `xml:"AttributeStatement"`
	Attribute []Attribute `xml:"Attribute"`
}

type Attribute struct {
	XMLName        xml.Name `xml:"Attribute"`
	Name           string   `xml:"Name,attr"`
	AttributeValue []string `xml:"AttributeValue"`
}

type RolesAndPrincipals struct {
	Role        string
	Principal   string
	Description string
}

type GroupsMetadata struct {
	Description string `json:"description"`
	Arn         string `json:"arn"`
}
