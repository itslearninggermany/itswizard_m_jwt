package itswizard_m_jwt

import (
	"encoding/json"
	"fmt"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/itslearninggermany/itswizard_m_uploadrest"
	"github.com/jinzhu/gorm"
	"net/http"
)

func CheckJWTRest(w http.ResponseWriter, r *http.Request, dbwebserver *gorm.DB) error {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return GetAuthKeys(dbwebserver).GetKey(), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
		Extractor: func(r *http.Request) (string, error) {
			tmp, err := itswizard_m_uploadrest.Decrypt(GetAuthKeys(dbwebserver).GetAes(), r.Header.Get("Authorization"))
			var auth Authentication
			err = json.Unmarshal([]byte(tmp), &auth)
			return auth.IDToken, err
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err string) {
			fmt.Fprint(w, err)
			return
		},
	})
	err := jwtMiddleware.CheckJWT(w, r)
	fmt.Println("sdfsdf")
	fmt.Println(err)
	return err
}
