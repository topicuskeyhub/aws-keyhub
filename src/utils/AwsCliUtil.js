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

const util = require('util');
const ConfigParser = require('configparser');
const os = require('os');
const path = require('path');
const fs = require('fs');
const AwsSts = require('aws-sdk/clients/sts');

const AWS_CONFIG_DIR = os.homedir() + path.sep + '.aws' + path.sep;

module.exports = {
    async configureWithSamlAssertion(roleArn, principalArn, samlAssertion, duration) {
        let credentials = await assumeRoleWithSaml(roleArn, principalArn, samlAssertion, duration);
        await writeCredentialFile(credentials);
    },

    async checkIfConfigFileExists() {
        try {
            await util.promisify(fs.access)(AWS_CONFIG_DIR + "config", fs.constants.F_OK);
        } catch (error) {
            throw new Error('It looks like you have no AWS configuration file.\nPlease run `aws configure` first. You can leave the access key fields empty.');
        }
    }
};

async function assumeRoleWithSaml(roleArn, principalArn, samlAssertion, duration) {
    const response = await stsAssumeRoleWithSAML(principalArn, roleArn, samlAssertion, duration);
    if (response !== null) {
        return {
            'accessKeyId': response.Credentials.AccessKeyId,
            'secretAccessKey': response.Credentials.SecretAccessKey,
            'sessionToken': response.Credentials.SessionToken
        };
    } else {
        throw new Error('Invalid AWS credentials retrieved.');
    }
}

function stsAssumeRoleWithSAML(principalArn, roleArn, samlAssertion, duration) {
    var sts = new AwsSts();
    var params = {
        PrincipalArn: principalArn,
        RoleArn: roleArn,
        SAMLAssertion: samlAssertion,
        DurationSeconds: duration,
    };

    return new Promise((resolve, reject) => {
        sts.assumeRoleWithSAML(params, function (err, data) {
            if (err) {
                console.error(err);
                throw err;
            }
            resolve(data);
        });
    });
}

async function writeCredentialFile(credentials) {
    const credentialFilePath = AWS_CONFIG_DIR + "credentials";
    await createFileIfNotExists(credentialFilePath);

    const credentialFile = new ConfigParser();
    credentialFile.read(credentialFilePath);

    if (!credentialFile.hasSection('keyhub')) {
        credentialFile.addSection('keyhub');
    }

    credentialFile.set('keyhub', 'aws_access_key_id', credentials.accessKeyId);
    credentialFile.set('keyhub', 'aws_secret_access_key', credentials.secretAccessKey);
    credentialFile.set('keyhub', 'aws_session_token', credentials.sessionToken);

    credentialFile.write(credentialFilePath);
}

function createFileIfNotExists(path) {
    return new Promise((resolve) => {
        fs.writeFile(path, '', {flag: 'a'}, (err) => {
            if (err)
                throw err;
            resolve();
        });
    });
}