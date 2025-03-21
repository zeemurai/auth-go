package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                  primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Email               string             `bson:"email" json:"email" validate:"required,email"`
	Password            string             `bson:"password" json:"-" validate:"required,min=8"`
	IsVerified          bool               `bson:"isVerified" json:"isVerified"`
	Status              string             `bson:"status" json:"status"`
	LoginOtp            *string            `bson:"loginOtp,omitempty" json:"-"`
	LoginOtpExpiresAt   *time.Time         `bson:"loginOtpExpiresAt,omitempty" json:"-"`
	SignupOtp           *string            `bson:"signupOtp,omitempty" json:"-"`
	SignupOtpExpiresAt  *time.Time         `bson:"signupOtpExpiresAt,omitempty" json:"-"`
	IsLocked            bool               `bson:"isLocked" json:"isLocked"`
	LockedAt            *time.Time         `bson:"lockedAt,omitempty" json:"lockedAt,omitempty"`
	FailedLoginAttempts int                `bson:"failedLoginAttempts" json:"-"`
	LastLogin           *time.Time         `bson:"lastLogin,omitempty" json:"lastLogin,omitempty"`
	CreatedAt           time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt           time.Time          `bson:"updatedAt" json:"updatedAt"`
}

// HashPassword creates a bcrypt hash of the password
func (u *User) HashPassword() error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	return nil
}

// ComparePassword checks if the provided password matches the stored hash
func (u *User) ComparePassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
}

// SetLoginOTP sets a new login OTP and its expiration time
func (u *User) SetLoginOTP(otp string) {
	u.LoginOtp = &otp
	expiresAt := time.Now().Add(5 * time.Minute)
	u.LoginOtpExpiresAt = &expiresAt
}

// ClearLoginOTP removes the login OTP and its expiration time
func (u *User) ClearLoginOTP() {
	u.LoginOtp = nil
	u.LoginOtpExpiresAt = nil
}

// IsLoginOTPValid checks if the provided OTP is valid and not expired
func (u *User) IsLoginOTPValid(otp string) bool {
	if u.LoginOtp == nil || u.LoginOtpExpiresAt == nil {
		return false
	}
	return *u.LoginOtp == otp && time.Now().Before(*u.LoginOtpExpiresAt)
}

// SetSignupOTP sets a new signup OTP and its expiration time
func (u *User) SetSignupOTP(otp string) {
	u.SignupOtp = &otp
	expiresAt := time.Now().Add(5 * time.Minute)
	u.SignupOtpExpiresAt = &expiresAt
}

// ClearSignupOTP removes the signup OTP and its expiration time
func (u *User) ClearSignupOTP() {
	u.SignupOtp = nil
	u.SignupOtpExpiresAt = nil
}

// IsSignupOTPValid checks if the provided signup OTP is valid and not expired
func (u *User) IsSignupOTPValid(otp string) bool {
	if u.SignupOtp == nil || u.SignupOtpExpiresAt == nil {
		return false
	}
	return *u.SignupOtp == otp && time.Now().Before(*u.SignupOtpExpiresAt)
}
