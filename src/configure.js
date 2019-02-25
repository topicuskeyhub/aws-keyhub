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

const constants = require.main.require('./constants.js');

const inquirer = require('inquirer');
const keytar = require('keytar');
const Configstore = require('configstore');
const config = new Configstore("aws-keyhub", {
    "keyhub": {
        "username": "",
        "url": ""
    },
    "aws": {
        "assumeDuration": ""
    }
}, {'configPath': constants.PATHS.AWS_KEYHUB.CONFIG});


module.exports = {

    configure: async function () {
        try {
            const answers = await promptUser();
            saveConfig(config, answers);
        } catch (error) {
            console.error(error);
            process.exit(1);
        }
    },

    hasValidConfiguration: async function () {
        const errorPrefix = "No valid aws-keyhub configuration found.";
        const errorSuffix = "Please run `aws-keyhub -c`.";

        const username = this.getUsername();
        if (username === null || username === undefined || username.length < 1) {
            throw new Error(`${errorPrefix}\nKeyHub username property is empty.\n${errorSuffix}`);
        }

        const password = await this.getPassword();
        if (password === null || password === undefined || password.length < 1) {
            throw new Error(`${errorPrefix}\nKeyHub password property is empty.\n${errorSuffix}`);
        }

        const url = this.getUrl();
        if (url === null || url === undefined || url.length < 1) {
            throw new Error(`${errorPrefix}\nKeyHub url property is empty.\n${errorSuffix}`);
        }

        const assumeDuration = this.getAssumeDuration();
        if (assumeDuration === null || assumeDuration === undefined || assumeDuration.length < 1) {
            throw new Error(`${errorPrefix}\nAWS assume role duration property is empty.\n${errorSuffix}`);
        }

        return true;
    },

    getUsername: function () {
        return get('keyhub.username');
    },

    getPassword: async function () {
        return await keytar.getPassword('aws-keyhub', this.getUsername());
    },

    getUrl: function () {
        return get('keyhub.url');
    },

    getAssumeDuration: function () {
        return get('aws.assumeDuration');
    },

    getKeyhubConfigDir: function () {
        return KEYHUB_CONFIG_DIR;
    }
};

function get(key) {
    return config.get(key);
}

async function promptUser() {
    return await inquirer.prompt([
        {
            type: 'text',
            name: 'username',
            message: 'KeyHub username'
        },
        {
            type: 'password',
            name: 'password',
            message: 'KeyHub password'
        },
        {
            type: 'text',
            name: 'url',
            message: 'KeyHub url',
            default: 'https://keyhub.domain.tld/login/initiate?client=urn:amazon:webservices'
        },
        {
            type: 'text',
            name: 'assumeDuration',
            message: 'AWS assume role duration (in seconds, max value is 43200)',
            default: '43200'
        }
    ]);
}

async function saveConfig(config, answers) {
    config.set('keyhub.username', answers.username);
    config.set('keyhub.url', answers.url);
    config.set('aws.assumeDuration', answers.assumeDuration);
    await keytar.setPassword('aws-keyhub', answers.username, answers.password)
}