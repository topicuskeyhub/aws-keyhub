package main

import (
	"bytes"
	"container/list"
	"encoding/json"
	"encoding/xml"
	"strings"
)

type Node struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",attr"`
	Content []byte     `xml:",innerxml"`
	Nodes   []Node     `xml:",any"`
}

func getAvailableKeyhubGroupsFromSaml(decoded []byte) *list.List {
	var groups = list.New()

	buf := bytes.NewBuffer(decoded)
	dec := xml.NewDecoder(buf)

	var n Node
	err := dec.Decode(&n)
	if err != nil {
		panic(err)
	}
	walk([]Node{n}, func(n Node) bool {
		if n.XMLName.Local == "Attribute" {
			if "https://github.com/topicuskeyhub/aws-keyhub/groups" == n.Attrs[0].Value {
				groups = getAvailableKeyhubGroups(n)
				return true
			}
		}
		return true
	})
	return groups
}

type ArnDescription struct {
	Description  string
	Arn          string
	SamlProvider string
}

func getAvailableKeyhubGroups(n Node) *list.List {
	result := list.New()

	for _, rek := range n.Nodes {
		var arnDescription ArnDescription
		err := json.Unmarshal(rek.Content, &arnDescription)
		if err != nil {
			panic(err)
		}
		splitParts := strings.Split(arnDescription.Arn, ",")
		arnDescription.Arn = splitParts[0]
		arnDescription.SamlProvider = splitParts[1]
		result.PushBack(&arnDescription)

	}
	return result
}

func walk(nodes []Node, f func(Node) bool) {
	for _, n := range nodes {
		if f(n) {
			walk(n.Nodes, f)
		}
	}
}

func (n *Node) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	n.Attrs = start.Attr
	type node Node

	return d.DecodeElement((*node)(n), &start)
}