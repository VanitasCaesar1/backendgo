package main

import (
	"github.com/VanitasCaesar1/backend/config"
	"github.com/workos/workos-go/v4/pkg/auditlogs"
	"github.com/workos/workos-go/v4/pkg/directorysync"
	"github.com/workos/workos-go/v4/pkg/organizations"
	"github.com/workos/workos-go/v4/pkg/passwordless"
	"github.com/workos/workos-go/v4/pkg/portal"
	"github.com/workos/workos-go/v4/pkg/sso"
	"github.com/workos/workos-go/v4/pkg/usermanagement"
)

func AuthkitInit(cfg config.Config) {
	// Initialize SSO with client ID and API key
	// Note: Changed to use two parameters as per compiler error
	sso.Configure(
		cfg.WorkOSClientId,
		cfg.WorkOSApiKey,
	)

	// Set API keys for other WorkOS services
	organizations.SetAPIKey(cfg.WorkOSOrganizationsKey)
	passwordless.SetAPIKey(cfg.WorkOSPasswordlessKey)
	directorysync.SetAPIKey(cfg.WorkOSDirectorySyncKey)
	usermanagement.SetAPIKey(cfg.WorkOSUserManagement)
	auditlogs.SetAPIKey(cfg.WorkOSAuditLogsKey)
	portal.SetAPIKey(cfg.WorkOSPortal)
}
