package aws_keyhub

import (
	"errors"
	"github.com/AlecAivazis/survey/v2"
	"github.com/sirupsen/logrus"
	"strings"
)

func SelectRoleAndPrincipal(roleArn string, rolesAndPrincipals map[string]RolesAndPrincipals) RolesAndPrincipals {
	if len(roleArn) > 0 {
		rolesAndPrincipal, err := findRoleAndPrincipalByOption(roleArn, rolesAndPrincipals)
		if err != nil {
			return promptForRole(rolesAndPrincipals)
		}
		logrus.Infoln("Selected role", rolesAndPrincipal.Role, "based on -r parameter.")
		return rolesAndPrincipal
	}

	return promptForRole(rolesAndPrincipals)
}

func promptForRole(rolesAndPrincipals map[string]RolesAndPrincipals) RolesAndPrincipals {
	var options []string
	for value := range rolesAndPrincipals {
		roleAndPrincipal := rolesAndPrincipals[value]
		options = append(options, roleAndPrincipal.Role+" / "+roleAndPrincipal.Description)
	}

	var selectedOption string
	err := survey.AskOne(&survey.Select{
		Message: "Choose a role",
		Options: options,
	}, &selectedOption)

	logrus.Debugln("User selected option:", selectedOption)
	if err != nil {
		logrus.Fatal("Failed to prompt user for role.", err)
	}

	rolesAndPrincipal, err := findRoleAndPrincipalByOption(selectedOption, rolesAndPrincipals)
	if err != nil {
		logrus.Fatal("Failed to find role and principal by role that the user selected in the prompt.", err)
	}

	return rolesAndPrincipal
}

func findRoleAndPrincipalByOption(selectedOption string, rolesAndPrincipals map[string]RolesAndPrincipals) (RolesAndPrincipals, error) {

	for value := range rolesAndPrincipals {
		roleAndPrincipal := rolesAndPrincipals[value]
		if strings.HasPrefix(selectedOption, roleAndPrincipal.Role) {
			logrus.Debug("Found role and principal by option:", selectedOption, roleAndPrincipal)
			return roleAndPrincipal, nil
		}
	}
	return RolesAndPrincipals{}, errors.New("unable to find matching Role and Principal based on user selected option")
}
