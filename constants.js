const os = require('os');
const path = require('path');

module.exports = {
    'PATHS': {
        'AWS_KEYHUB': {
            'CONFIG': os.homedir() + path.sep + '.aws-keyhub' + path.sep + 'config.json',
            'PUPPETEER_PROFILE': os.homedir() + path.sep + '.aws-keyhub' + path.sep + 'puppeteer_profile' + path.sep
        },
        'AWS_CLI': {
            'CONFIG': os.homedir() + path.sep + '.aws' + path.sep + 'config',
            'CREDENTIALS': os.homedir() + path.sep + '.aws' + path.sep + 'credentials'
        }
    }
};