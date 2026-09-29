package aws_keyhub

import (
	"errors"
	"slices"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/sirupsen/logrus"
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
	var options []huh.Option[RolesAndPrincipals]
	for value := range rolesAndPrincipals {
		roleAndPrincipal := rolesAndPrincipals[value]
		options = append(options, huh.NewOption(roleAndPrincipal.Role+" / "+roleAndPrincipal.Description, roleAndPrincipal))
	}
	slices.SortFunc(options, func(a, b huh.Option[RolesAndPrincipals]) int {
		return strings.Compare(a.Key, b.Key)
	})

	var selected RolesAndPrincipals
	err := huh.NewSelect[RolesAndPrincipals]().
		Title("Choose a role").
		Options(options...).
		Filtering(true).
		Value(&selected).
		Run()
	if err != nil {
		logrus.Fatal("Failed to prompt user for role.", err)
	}

	logrus.Debugln("User selected role:", selected.Role)
	return selected
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
