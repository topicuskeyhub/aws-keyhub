// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const parser = require('fast-xml-parser');
const atob = require('atob');

module.exports = {

    getSamlResponse(interceptedRequest) {
        return interceptedRequest.postData().replace('SAMLResponse=', '');
    },

    getBase64SamlResponse(samlResponse) {
        return decodeURIComponent(samlResponse);
    },

    getDecodedSamlResponse(samlResponseBase64) {
        return atob(samlResponseBase64);
    },

    getRolesAndPrincipalsFromSamlResponse(samlResponseDecoded) {
        let rolesAndPrincipals = new Map();
        const result = parser.parse(samlResponseDecoded, {ignoreAttributes: false});

        let samlAttributes = result['saml2p:Response']['saml2:Assertion']['saml2:AttributeStatement']['saml2:Attribute'];
        samlAttributes.forEach(async element => {
            if (element['@_Name'] === 'https://aws.amazon.com/SAML/Attributes/Role') {
                rolesAndPrincipals = processAttributeRole(element, rolesAndPrincipals);
            }

            if (element['@_Name'] === 'https://github.com/topicuskeyhub/aws-keyhub/groups') {
                rolesAndPrincipals = processAttributeKeyhubGroup(element, rolesAndPrincipals);
            }
        });

        return Array.from(rolesAndPrincipals.values());
    }
}

function processAttributeRole(element, rolesAndPrincipals) {
    element['saml2:AttributeValue'] = putObjectInArrayIfPlain(element['saml2:AttributeValue']);
    element['saml2:AttributeValue'].forEach(attribute => {
        const roleAndPrincipal = attribute['#text'];
        let role, principal;

        roleAndPrincipal.split(',').forEach(roleOrPrincipal => {
            if (roleOrPrincipal.indexOf('role') > -1)
                role = roleOrPrincipal;
            if (roleOrPrincipal.indexOf('saml-provider') > -1)
                principal = roleOrPrincipal;
        });

        if (rolesAndPrincipals.get(role)) {
            let currentValue = rolesAndPrincipals.get(role);
            currentValue['role'] = role;
            currentValue['principal'] = principal;
            rolesAndPrincipals.set(role, currentValue);
        } else {
            rolesAndPrincipals.set(role, {'role': role, 'principal': principal});
        }
    });

    return rolesAndPrincipals;
}

function processAttributeKeyhubGroup(element, rolesAndPrincipals) {
    element['saml2:AttributeValue'] = putObjectInArrayIfPlain(element['saml2:AttributeValue']);
    element['saml2:AttributeValue'].forEach(attribute => {
        let parsedJson = JSON.parse(attribute['#text']);
        const keyHubGroupDescription = parsedJson.description;
        const keyHubGroupAwsArn = parsedJson.arn;

        keyHubGroupAwsArn.split(',').forEach(roleOrPrincipal => {
            if (roleOrPrincipal.indexOf('role') > -1) {
                let role = roleOrPrincipal;
                rolesAndPrincipals.set(role, {'description': keyHubGroupDescription});
            }
        });
    });

    return rolesAndPrincipals;
}

function putObjectInArrayIfPlain(element) {
    if (!Array.isArray(element)) {
        element = [element];
    }

    return element;
}