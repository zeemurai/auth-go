package utils

import (
	"crypto/rand"
)

// GenerateOTP generates a random OTP of the specified length
func GenerateOTP(length int) (string, error) {
	const digits = "0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	otp := make([]byte, length)
	for i := 0; i < length; i++ {
		otp[i] = digits[int(b[i])%len(digits)]
	}
	return string(otp), nil
}
