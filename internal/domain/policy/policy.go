// Package policy holds the authorisation model: who may do what, and the
// ownership rule used to prevent IDOR.
package policy

import "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"

// Actor is the authenticated principal carried in the request context.
type Actor struct {
	ID    uint
	Role  entity.Role
	Perms []entity.Permission
}

// NewActor builds an Actor for a role, expanding the role into permissions.
func NewActor(id uint, role entity.Role) Actor {
	return Actor{ID: id, Role: role, Perms: PermissionsFor(role)}
}

// IsAdmin reports whether the actor has the admin role.
func (a Actor) IsAdmin() bool { return a.Role == entity.RoleAdmin }

// Can reports whether the actor holds perm.
func (a Actor) Can(perm entity.Permission) bool {
	for _, p := range a.Perms {
		if p == perm {
			return true
		}
	}
	return false
}

var allPermissions = []entity.Permission{
	entity.PermScanCreate, entity.PermScanRead, entity.PermScanCancel,
	entity.PermCredCreate, entity.PermCredRead, entity.PermCredUpdate,
	entity.PermCredDelete, entity.PermCredVerify,
	entity.PermTicketCreate, entity.PermTicketUpdate,
	entity.PermReportGenerate, entity.PermReportDownload,
	entity.PermUserManage, entity.PermAuditView,
}

// PermissionsFor expands a role into its permission set. Deny by default:
// unknown roles get nothing.
func PermissionsFor(role entity.Role) []entity.Permission {
	switch role {
	case entity.RoleAdmin:
		return allPermissions
	case entity.RoleSecurityAnalyst:
		return []entity.Permission{
			entity.PermScanCreate, entity.PermScanRead, entity.PermScanCancel,
			entity.PermCredCreate, entity.PermCredRead, entity.PermCredUpdate,
			entity.PermCredDelete, entity.PermCredVerify,
			entity.PermTicketCreate, entity.PermTicketUpdate,
			entity.PermReportGenerate, entity.PermReportDownload,
		}
	case entity.RoleAuditor:
		return []entity.Permission{
			entity.PermScanRead, entity.PermCredRead,
			entity.PermReportGenerate, entity.PermReportDownload,
			entity.PermAuditView,
		}
	case entity.RoleViewer:
		return []entity.Permission{
			entity.PermScanRead, entity.PermReportDownload,
		}
	default:
		return nil
	}
}

// CanAccessOwner is the ownership rule: admins may read anything, everybody
// else only their own rows.
func (a Actor) CanAccessOwner(ownerID uint) bool {
	return a.IsAdmin() || a.ID == ownerID
}
