package itswizard_m_jwt

import (
	"fmt"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"net/http"
	"time"
)

type RefreshToken struct {
	gorm.Model
	RefreshToken string `gorm:"unique"`
	Username     string
}

func createRefreshToken(username string) *RefreshToken {
	re := new(RefreshToken)
	u1 := uuid.Must(uuid.NewV4())
	re.RefreshToken = u1.String()
	re.Username = username
	return re
}

func (p *RefreshToken) String() string {
	return p.RefreshToken
}

func (p *RefreshToken) StoreInDatatbae(dbWebserver *gorm.DB) error {
	return dbWebserver.Save(&p).Error
}

func Authentificate(r *http.Request) string {

	return ""
}

func getRefreshTokenFromDatabase(username string, dbWebserver *gorm.DB) (*RefreshToken, error) {
	var rToken RefreshToken
	err := dbWebserver.Where("username = ?", username).Last(&rToken).Error
	return &rToken, err
}

func GetRefreshTokenFromDatatabse(tokenID string, dbWebserver *gorm.DB) *RefreshToken {
	var rt RefreshToken
	err := dbWebserver.Where("refresh_token = ?", tokenID).Last(&rt).Error
	if err != nil {
		fmt.Println(err)
	}
	return &rt
}

func (p *RefreshToken) Valid(username string) bool {
	// Check if Token is in Database:
	exist := false
	if p.Username == username {
		exist = true
	} else {
		fmt.Println(p.Username, username)
		return false
	}

	if exist {
		if getMinutesScinceCreatet(p.CreatedAt) > 70 {
			fmt.Println(getMinutesScinceCreatet(p.CreatedAt))
			return false
		} else {
			fmt.Println(getMinutesScinceCreatet(p.CreatedAt))
			return true
		}
	} else {
		return false
	}
}

func getMinutesScinceCreatet(input time.Time) float64 {
	aus := time.Now().Sub(input)
	return aus.Minutes()
}
