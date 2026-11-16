package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

type userRepository struct{ db *gorm.DB }

// NewUserRepository returns a Postgres-backed UserRepository.
func NewUserRepository(db *gorm.DB) repository.UserRepository { return &userRepository{db: db} }

func (r *userRepository) Create(ctx context.Context, u *entity.User) error {
	if r.db == nil {
		return errNoDB
	}
	m := userFromEntity(u)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		if isUniqueViolation(err) {
			return apperr.NewAppError("CONFLICT", "Username or email already exists", 409)
		}
		return err
	}
	u.ID = m.ID
	u.CreatedAt = m.CreatedAt
	u.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *userRepository) FindByID(ctx context.Context, id uint) (*entity.User, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	var m User
	if err := r.db.WithContext(ctx).First(&m, id).Error; err != nil {
		return nil, mapGormError(err)
	}
	return m.toEntity(), nil
}

func (r *userRepository) FindByUsername(ctx context.Context, username string) (*entity.User, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	var m User
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(&m).Error; err != nil {
		return nil, mapGormError(err)
	}
	return m.toEntity(), nil
}

func (r *userRepository) Update(ctx context.Context, u *entity.User) error {
	if r.db == nil {
		return errNoDB
	}
	updates := map[string]any{
		"email":         u.Email,
		"password_hash": u.PasswordHash,
		"role":          string(u.Role),
		"is_active":     u.IsActive,
		"last_login":    u.LastLogin,
	}
	res := r.db.WithContext(ctx).Model(&User{}).Where("id = ?", u.ID).Updates(updates)
	if res.Error != nil {
		if isUniqueViolation(res.Error) {
			return apperr.NewAppError("CONFLICT", "Email already exists", 409)
		}
		return res.Error
	}
	if res.RowsAffected == 0 {
		return apperr.ErrNotFound
	}
	return nil
}
