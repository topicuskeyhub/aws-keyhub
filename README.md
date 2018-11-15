# aws-keyhub
CLI login helper for the [AWS CLI](https://aws.amazon.com/cli/) when using SAML based federated login with [Topicus KeyHub](https://www.topicus-keyhub.com).

## Usage

### Installation

#### Release version
Run `npm install -g aws-keyhub`

#### Development version
Installing the development version is easy.
1. Checkout this git repository
2. Change current working directory to the aws-keyhub directory
3. Run `npm link`

### Configuration
To set-up the aws-keyhub tool we need the KeyHub username, password and url. Configuring these properties can be done by running with the `-c` param: `aws-keyhub -c`
*Note: the KeyHub url should be the SAML IDP initiated-flow url. It's similar to: https://keyhub.domain.tld/login/initiate?client=urn:amazon:webservices*

### Authenticate
When the application is configured you can run the tool by executing `aws-keyhub`.
It will prompt you for the 2FA token and the role you want to use. This roles are the AWS roles that you have access to in one or more AWS accounts.

### Session duration
Due to [restrictions by Amazon Web Services](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html) the maximum duration of the session is 12 hours. If authentication fails when using the AWS CLI please re-run the `aws-keyhub` command. The default session duration is 12 hours (43200 sec). If you need a shorter duration please reconfigure with `aws-keyhub -c`.

## Topicus KeyHub configuration
For optimal usage of this tool your KeyHub instance needs to be configured to send additional SAML payload. The payload helps a user to select the right role if they have access to multiple AWS accounts by displaying a description. Add the custom attribute ```https://github.com/topicuskeyhub/aws-keyhub/groups``` with the following code to build the descriptive array.

```javascript
// Function returns a list of descriptive objects based on a UUID match
var mapping = new Map();
mapping.set('aaabbbcc-2222-aaaa-3333-fffff0000000', {
    'account' : 'example-account-name',
    'role' : 'inzicht',
    'arn' : 'arn:aws:iam::123456789012:role/MyCustomRole,arn:aws:iam::123456789012:saml-provider/keyhub'
});

return groups.filter(function (group) {
    return mapping.has(group.uuid);
  }).map(function (group) {
    return "{\"description\": \"" + mapping.get(group.uuid).account + " - " + mapping.get(group.uuid).role + "\", \"arn\": \"" + mapping.get(group.uuid).arn + "\"}";
  });
```

## FAQ
* How is my KeyHub password stored?
To make the login process as easy as possible we store your password when running the configure command. To make sure it's stored safely we use keytar. Keytar stores the password in a native way depending on your operating system. For MacOS the native Keychain is used, for Windows keytar relies on Credential Vault. On Linux the libsecret library is used. More information about keytar is found here: https://www.npmjs.com/package/keytar

* Where is the configuration stored?
The configuration is stored in ```~/.aws-keyhub/config.json```

* Help! The login flow is broken, something seems to be corrupt.
aws-keyhub uses headless Chrome to login. It is possible that something is wrong with your Chrome profile. If this occures you can delete the Chrome profile which can be found at ```~/.aws-keyhub/puppeteer_profile```
