package postgres

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/secretbox"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

type credentialRepository struct {
	db  *gorm.DB
	box *secretbox.Box
}

// NewAuthCredentialRepository returns a Postgres-backed credential repository.
// When box is provided, the credential config is encrypted at rest.
func NewAuthCredentialRepository(db *gorm.DB, box ...*secretbox.Box) repository.AuthCredentialRepository {
	r := &credentialRepository{db: db}
	if len(box) > 0 {
		r.box = box[0]
	}
	return r
}

// encryptConfig serialises the config and encrypts it. Without a cipher the
// value is stored as plain JSON (development fallback) and a warning is logged.
func (r *credentialRepository) encryptConfig(config map[string]any) datatypes.JSON {
	plain, err := json.Marshal(config)
	if err != nil {
		return datatypes.JSON([]byte("null"))
	}
	if r.box == nil {
		return datatypes.JSON(plain)
	}
	ct, err := r.box.Encrypt(plain)
	if err != nil {
		log.Printf("postgres: credential encryption failed: %v", err)
		return datatypes.JSON([]byte("null"))
	}
	return encodeString(ct)
}

func (r *credentialRepository) decryptConfig(raw datatypes.JSON) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		// Legacy plaintext object written before encryption was enabled.
		return decodeMap(raw)
	}
	if r.box == nil {
		return nil
	}
	plain, err := r.box.Decrypt(encoded)
	if err != nil {
		log.Printf("postgres: credential decryption failed: %v", err)
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil
	}
	return out
}

func (r *credentialRepository) Create(ctx context.Context, c *entity.AuthCredential) error {
	if r.db == nil {
		return errNoDB
	}
	m := credentialFromEntity(c)
	m.Config = r.encryptConfig(c.Config)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	c.ID = m.ID
	c.CreatedAt = m.CreatedAt
	c.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *credentialRepository) FindByID(ctx context.Context, id uint) (*entity.AuthCredential, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	var m AuthCredential
	if err := r.db.WithContext(ctx).First(&m, id).Error; err != nil {
		return nil, mapGormError(err)
	}
	e := m.toEntity()
	e.Config = r.decryptConfig(m.Config)
	return e, nil
}

func (r *credentialRepository) FindByIDOwned(ctx context.Context, id, userID uint) (*entity.AuthCredential, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	var m AuthCredential
	if err := r.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).First(&m).Error; err != nil {
		return nil, mapGormError(err)
	}
	e := m.toEntity()
	e.Config = r.decryptConfig(m.Config)
	return e, nil
}

func (r *credentialRepository) FindByUserID(ctx context.Context, userID uint) ([]*entity.AuthCredential, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	var rows []AuthCredential
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*entity.AuthCredential, 0, len(rows))
	for i := range rows {
		e := rows[i].toEntity()
		e.Config = r.decryptConfig(rows[i].Config)
		out = append(out, e)
	}
	return out, nil
}

func (r *credentialRepository) Update(ctx context.Context, c *entity.AuthCredential) error {
	if r.db == nil {
		return errNoDB
	}
	updates := map[string]any{
		"name":           c.Name,
		"method":         string(c.Method),
		"config":         r.encryptConfig(c.Config),
		"login_url":      c.LoginURL,
		"verify_url":     c.VerifyURL,
		"verify_pattern": c.VerifyPattern,
		"is_active":      c.IsActive,
	}
	res := r.db.WithContext(ctx).Model(&AuthCredential{}).
		Where("id = ? AND user_id = ?", c.ID, c.UserID).
		Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

// DeleteOwned deletes only when the credential belongs to userID.
func (r *credentialRepository) DeleteOwned(ctx context.Context, id, userID uint) error {
	if r.db == nil {
		return errNoDB
	}
	res := r.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).Delete(&AuthCredential{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

func (r *credentialRepository) UpdateLastVerified(ctx context.Context, id uint) error {
	if r.db == nil {
		return errNoDB
	}
	now := time.Now()
	res := r.db.WithContext(ctx).Model(&AuthCredential{}).Where("id = ?", id).
		Updates(map[string]any{"last_verified": now})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

type auditLogRepository struct{ db *gorm.DB }

// NewAuditLogRepository returns a Postgres-backed audit log repository.
func NewAuditLogRepository(db *gorm.DB) repository.AuditLogRepository {
	return &auditLogRepository{db: db}
}

func (r *auditLogRepository) Create(ctx context.Context, entry *repository.AuditLogEntry) error {
	if r.db == nil {
		return errNoDB
	}
	m := &AuditLog{
		UserID:   entry.UserID,
		Level:    entry.Level,
		Category: entry.Category,
		Action:   entry.Action,
		Message:  entry.Message,
		Metadata: encodeJSON(entry.Metadata),
	}
	return r.db.WithContext(ctx).Create(m).Error
}
