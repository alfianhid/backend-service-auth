// Package secure contains support for application security
package secure

import (
	"hash"

	zxcvbn "github.com/nbutton23/zxcvbn-go"
	"golang.org/x/crypto/bcrypt"
)

func New(minPWStr int, h hash.Hash) *Service {
	return &Service{minPWStr: minPWStr, h: h}
}

type Service struct {
	minPWStr int
	h        hash.Hash
}

func (s *Service) Password(pass string, inputs ...string) bool {
	pwStrength := zxcvbn.PasswordStrength(pass, inputs)
	return pwStrength.Score >= s.minPWStr
}

func (*Service) Hash(password string) string {
	hashedPW, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashedPW)
}

func (*Service) HashMatchesPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
