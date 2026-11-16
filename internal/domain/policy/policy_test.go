package policy

import (
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
)

func TestPermissionsForRole(t *testing.T) {
	tests := []struct {
		role    entity.Role
		perm    entity.Permission
		allowed bool
	}{
		{entity.RoleAdmin, entity.PermUserManage, true},
		{entity.RoleSecurityAnalyst, entity.PermScanCreate, true},
		{entity.RoleSecurityAnalyst, entity.PermUserManage, false},
		{entity.RoleAuditor, entity.PermScanRead, true},
		{entity.RoleAuditor, entity.PermScanCreate, false},
		{entity.RoleViewer, entity.PermScanRead, true},
		{entity.RoleViewer, entity.PermScanCreate, false},
		{entity.RoleViewer, entity.PermCredRead, false},
		{"unknown-role", entity.PermScanRead, false},
	}
	for _, tc := range tests {
		actor := NewActor(1, tc.role)
		if got := actor.Can(tc.perm); got != tc.allowed {
			t.Errorf("role=%s perm=%s: Can()=%v want %v", tc.role, tc.perm, got, tc.allowed)
		}
	}
}

func TestCanAccessOwner(t *testing.T) {
	owner := NewActor(7, entity.RoleSecurityAnalyst)
	if !owner.CanAccessOwner(7) {
		t.Error("actor should access its own resource")
	}
	if owner.CanAccessOwner(8) {
		t.Error("actor must not access another user's resource")
	}

	admin := NewActor(1, entity.RoleAdmin)
	if !admin.CanAccessOwner(8) {
		t.Error("admin should access any resource")
	}
}
