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
const exec = util.promisify(require('child_process').exec);
const ConfigParser = require('configparser');
const os = require('os');

module.exports = {
    async configureWithSamlAssertion(roleArn, principalArn, samlAssertion, duration) {
        let credentials = await assumeRoleWithSaml(roleArn, principalArn, samlAssertion, duration);
        writeConfigFile(credentials);
    }
}

async function assumeRoleWithSaml(roleArn, principalArn, samlAssertion, duration) {
    try {
        const { stdout } = await exec('aws sts assume-role-with-saml --duration-seconds=' + duration + ' --role-arn ' + roleArn + ' --principal-arn ' + principalArn + ' --saml-assertion ' + samlAssertion);

        if (stdout.indexOf('AccessKeyId') > -1 && stdout.indexOf('SecretAccessKey' > -1) && stdout.indexOf('SessionToken') > -1) {
            const credentials = JSON.parse(stdout).Credentials;
            return {
                'accessKeyId': credentials.AccessKeyId,
                'secretAccessKey': credentials.SecretAccessKey,
                'sessionToken': credentials.SessionToken
            };
        } else {
            throw new Error('Invalid AWS credentials retrieved.');
        }
    } catch (error) {
        console.log(error);
    }
}

function writeConfigFile(credentials) {
    const configFilePath = os.homedir() + '/.aws/credentials';
    const config = new ConfigParser();
    config.read(configFilePath);

    if (!config.hasSection('keyhub'))
        config.addSection('keyhub')

    config.set('keyhub', 'aws_access_key_id', credentials.accessKeyId);
    config.set('keyhub', 'aws_secret_access_key', credentials.secretAccessKey);
    config.set('keyhub', 'aws_session_token', credentials.sessionToken);

    config.write(configFilePath);
}