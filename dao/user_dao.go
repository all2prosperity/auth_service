package dao

import (
	"fmt"
	"time"

	"github.com/all2prosperity/auth_service/database"
	"github.com/all2prosperity/auth_service/models"

	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"
)

// UserDAO handles user-related database operations
type UserDAO struct {
	db *database.DB
}

// NewUserDAO creates a new UserDAO
func NewUserDAO(db *database.DB) *UserDAO {
	return &UserDAO{db: db}
}

// CreateUser creates a new user
func (dao *UserDAO) CreateUser(user *models.User) error {
	result := dao.db.Create(user)
	if result.Error != nil {
		return fmt.Errorf("failed to create user: %w", result.Error)
	}
	return nil
}

// GetUserByID retrieves a user by ID
func (dao *UserDAO) GetUserByID(id string) (*models.User, error) {
	var user models.User
	result := dao.db.Where("id = ?", id).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", result.Error)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (dao *UserDAO) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	result := dao.db.Where("email = ?", email).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", result.Error)
	}
	return &user, nil
}

// GetUserByPhoneNumber retrieves a user by phone number
func (dao *UserDAO) GetUserByPhoneNumber(phoneNumber string) (*models.User, error) {
	var user models.User
	result := dao.db.Where("phone_number = ?", phoneNumber).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", result.Error)
	}
	return &user, nil
}

// GetUserByIdentifier retrieves a user by email or phone number
func (dao *UserDAO) GetUserByIdentifier(identifier string) (*models.User, error) {
	var user models.User
	result := dao.db.Where("email = ? OR phone_number = ?", identifier, identifier).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", result.Error)
	}
	return &user, nil
}

// UpdateUser updates a user
func (dao *UserDAO) UpdateUser(user *models.User) error {
	result := dao.db.Save(user)
	if result.Error != nil {
		return fmt.Errorf("failed to update user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// UpdateUserPassword updates a user's password
func (dao *UserDAO) UpdateUserPassword(userID ulid.ULID, passwordHash string) error {
	result := dao.db.Model(&models.User{}).Where("id = ?", userID).Update("password_hash", passwordHash)
	if result.Error != nil {
		return fmt.Errorf("failed to update user password: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// UpdateUserRoles updates a user's roles
func (dao *UserDAO) UpdateUserRoles(userID ulid.ULID, roles []string) error {
	result := dao.db.Model(&models.User{}).Where("id = ?", userID).Update("roles", roles)
	if result.Error != nil {
		return fmt.Errorf("failed to update user roles: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// ConfirmUser confirms a user's email/phone
func (dao *UserDAO) ConfirmUser(userID ulid.ULID) error {
	now := time.Now()
	result := dao.db.Model(&models.User{}).Where("id = ?", userID).Update("confirmed_at", &now)
	if result.Error != nil {
		return fmt.Errorf("failed to confirm user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// LockUser locks a user until the specified time
func (dao *UserDAO) LockUser(userID ulid.ULID, until time.Time) error {
	result := dao.db.Model(&models.User{}).Where("id = ?", userID).Update("locked_until", &until)
	if result.Error != nil {
		return fmt.Errorf("failed to lock user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// UnlockUser unlocks a user
func (dao *UserDAO) UnlockUser(userID ulid.ULID) error {
	result := dao.db.Model(&models.User{}).Where("id = ?", userID).Update("locked_until", nil)
	if result.Error != nil {
		return fmt.Errorf("failed to unlock user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// DeleteUser soft deletes a user
func (dao *UserDAO) DeleteUser(userID ulid.ULID) error {
	result := dao.db.Delete(&models.User{}, userID)
	if result.Error != nil {
		return fmt.Errorf("failed to delete user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// HardDeleteUser permanently deletes a user
func (dao *UserDAO) HardDeleteUser(userID ulid.ULID) error {
	result := dao.db.Unscoped().Delete(&models.User{}, userID)
	if result.Error != nil {
		return fmt.Errorf("failed to hard delete user: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// ListUsers lists users with pagination
func (dao *UserDAO) ListUsers(offset, limit int) ([]*models.User, error) {
	var users []*models.User
	result := dao.db.Offset(offset).Limit(limit).Order("created_at DESC").Find(&users)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to list users: %w", result.Error)
	}
	return users, nil
}

// CountUsers returns the total number of users
func (dao *UserDAO) CountUsers() (int64, error) {
	var count int64
	result := dao.db.Model(&models.User{}).Count(&count)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count users: %w", result.Error)
	}
	return count, nil
}

// GetUserWithSocialAccounts retrieves a user with their social accounts
func (dao *UserDAO) GetUserWithSocialAccounts(userID ulid.ULID) (*models.User, error) {
	var user models.User
	result := dao.db.Preload("SocialAccounts").Where("id = ?", userID).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user with social accounts: %w", result.Error)
	}
	return &user, nil
}

// CreateSocialAccount creates a new social account binding
func (dao *UserDAO) CreateSocialAccount(socialAccount *models.SocialAccount) error {
	result := dao.db.Create(socialAccount)
	if result.Error != nil {
		return fmt.Errorf("failed to create social account: %w", result.Error)
	}
	return nil
}

// GetSocialAccount retrieves a social account by provider and provider UID
func (dao *UserDAO) GetSocialAccount(provider, providerUID string) (*models.SocialAccount, error) {
	var socialAccount models.SocialAccount
	result := dao.db.Where("provider = ? AND provider_uid = ?", provider, providerUID).First(&socialAccount)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("social account not found")
		}
		return nil, fmt.Errorf("failed to get social account: %w", result.Error)
	}
	return &socialAccount, nil
}

// DeleteSocialAccount deletes a social account for a user
func (dao *UserDAO) DeleteSocialAccount(userID ulid.ULID, provider string) error {
	result := dao.db.Where("user_id = ? AND provider = ?", userID, provider).Delete(&models.SocialAccount{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete social account: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("social account not found")
	}
	return nil
}

// SearchUsers searches users by email or phone number with pagination
func (dao *UserDAO) SearchUsers(query string, offset, limit int) ([]*models.User, error) {
	var users []*models.User
	searchPattern := "%" + query + "%"
	result := dao.db.Where("email ILIKE ? OR phone_number ILIKE ?", searchPattern, searchPattern).
		Offset(offset).Limit(limit).Order("created_at DESC").Find(&users)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to search users: %w", result.Error)
	}
	return users, nil
}

// GetUsersWithRole returns all users with a specific role
func (dao *UserDAO) GetUsersWithRole(role string) ([]*models.User, error) {
	var users []*models.User
	result := dao.db.Where("? = ANY(roles)", role).Find(&users)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get users with role: %w", result.Error)
	}
	return users, nil
}

// UpdateLastLogin updates the user's last login time
func (dao *UserDAO) UpdateLastLogin(userID ulid.ULID) error {
	// Note: This would update a last_login_at field if it exists in the User model
	// For now, we'll just return nil as the User model doesn't have this field
	return nil
}
