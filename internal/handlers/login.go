package handlers

import (
	"net/http"
	"time"

	"auth-go/internal/models"
	"auth-go/internal/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	maxFailedAttempts = 5
	lockTime          = 15 * time.Minute
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginVerifyRequest struct {
	Email string `json:"email" binding:"required,email"`
	OTP   string `json:"otp" binding:"required,len=6"`
}

// Login handles the first step of the login process
func Login(db *mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Find user by email
		var user models.User
		err := db.Collection("users").FindOne(c, bson.M{"email": req.Email}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Check if account is deactivated
		if user.Status == "deactivated" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Account is deactivated"})
			return
		}

		// Check if account is locked
		if user.IsLocked {
			if user.LockedAt != nil {
				timeSinceLock := time.Since(*user.LockedAt)
				if timeSinceLock < lockTime {
					remainingTime := lockTime - timeSinceLock
					c.JSON(http.StatusForbidden, gin.H{
						"error":            "Account is locked",
						"remainingMinutes": int(remainingTime.Minutes()),
					})
					return
				}
				// Reset lock if lock time has passed
				user.IsLocked = false
				user.FailedLoginAttempts = 0
				user.LockedAt = nil
			}
		}

		// Check if email is verified
		if !user.IsVerified {
			otp, err := utils.GenerateOTP(6)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
				return
			}

			user.SetSignupOTP(otp)
			_, err = db.Collection("users").UpdateOne(c, bson.M{"_id": user.ID}, bson.M{
				"$set": bson.M{
					"signupOtp":          user.SignupOtp,
					"signupOtpExpiresAt": user.SignupOtpExpiresAt,
				},
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
				return
			}

			err = utils.SendEmail(&utils.EmailData{
				To:      user.Email,
				Subject: "Verify email address (expires in 5 minutes)",
				Text:    "Your OTP code is: " + otp,
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"status":  "success",
				"message": "Verification OTP sent to email address",
			})
			return
		}

		// Verify password
		if err := user.ComparePassword(req.Password); err != nil {
			user.FailedLoginAttempts++
			if user.FailedLoginAttempts >= maxFailedAttempts {
				now := time.Now()
				user.IsLocked = true
				user.LockedAt = &now

				err = utils.SendEmail(&utils.EmailData{
					To:      user.Email,
					Subject: "Account Locked Due to Multiple Failed Login Attempts",
					Text:    "Your account has been locked due to too many failed login attempts. Please try again in 15 minutes.",
				})
				if err != nil {
					// Log the error but continue with the response
					// TODO: Implement proper logging
				}
			}

			_, err = db.Collection("users").UpdateOne(c, bson.M{"_id": user.ID}, bson.M{
				"$set": bson.M{
					"failedLoginAttempts": user.FailedLoginAttempts,
					"isLocked":            user.IsLocked,
					"lockedAt":            user.LockedAt,
				},
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
				return
			}

			if user.IsLocked {
				c.JSON(http.StatusForbidden, gin.H{"error": "Account locked due to too many failed attempts"})
				return
			}

			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Generate and send OTP
		otp, err := utils.GenerateOTP(6)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
			return
		}

		user.SetLoginOTP(otp)
		user.FailedLoginAttempts = 0

		_, err = db.Collection("users").UpdateOne(c, bson.M{"_id": user.ID}, bson.M{
			"$set": bson.M{
				"loginOtp":            user.LoginOtp,
				"loginOtpExpiresAt":   user.LoginOtpExpiresAt,
				"failedLoginAttempts": 0,
			},
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
			return
		}

		err = utils.SendEmail(&utils.EmailData{
			To:      user.Email,
			Subject: "Login verification (expires in 5 minutes)",
			Text:    otp,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP email"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": "Please check your email",
		})
	}
}

// VerifyLogin handles the second step of the login process
func VerifyLogin(db *mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginVerifyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		var user models.User
		err := db.Collection("users").FindOne(c, bson.M{
			"email":             req.Email,
			"loginOtp":          req.OTP,
			"loginOtpExpiresAt": bson.M{"$gt": time.Now()},
		}).Decode(&user)

		if err != nil {
			if err == mongo.ErrNoDocuments {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired code"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify OTP"})
			return
		}

		// Clear OTP and update last login
		now := time.Now()
		_, err = db.Collection("users").UpdateOne(c, bson.M{"_id": user.ID}, bson.M{
			"$set": bson.M{
				"lastLogin":         now,
				"loginOtp":          nil,
				"loginOtpExpiresAt": nil,
			},
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
			return
		}

		// Generate JWT token
		token, err := utils.GenerateToken(user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": "Login successful",
			"token":   token,
		})
	}
}
