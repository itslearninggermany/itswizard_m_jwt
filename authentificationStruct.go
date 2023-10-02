package itswizard_m_jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itslearninggermany/itswizard_m_uploadrest"
	"github.com/jinzhu/gorm"
	"net/http"
	"net/url"
)

type Authentication struct {
	AccessToken  string `json:"AccessToken"`
	ExpiresIn    uint   `json:"ExpiresIn"`
	IDToken      string `json:"IdToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
}

func setAuthentification(AccessToken, IDToken, RefreshToken string) *Authentication {
	a := new(Authentication)
	a.ExpiresIn = 3600
	a.AccessToken = AccessToken
	a.IDToken = IDToken
	a.RefreshToken = RefreshToken
	a.TokenType = "Bearer"
	return a
}

func (a *Authentication) String() string {
	out, _ := json.Marshal(a)
	return string(out)
}

func CreateNewAuthUrl(AccessToken, IDToken, RefreshToken string, dbWebserver *gorm.DB) string {
	authentification := setAuthentification(AccessToken, IDToken, RefreshToken)
	out, err := itswizard_m_uploadrest.Encrypt(GetAuthKeys(dbWebserver).GetAes(), authentification.String())
	if err != nil {
		fmt.Println(err)
	}
	return fmt.Sprint(out)
}

func DecodeAuthentification(r *http.Request, dbWebserver *gorm.DB) (auth Authentication, err error) {
	res := r.URL.Query()["key"]
	if len(res) == 0 {
		return auth, errors.New("no token")
	} else {
		token, err := url.PathUnescape(res[0])
		if err != nil {
			return auth, err
		}
		tmp, err := itswizard_m_uploadrest.Decrypt(GetAuthKeys(dbWebserver).GetAes(), token)
		if err != nil {
			return auth, err
		}
		err = json.Unmarshal([]byte(tmp), &auth)
	}
	return
}
