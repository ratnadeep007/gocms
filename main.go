package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/rs/cors"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB
var err error

func main() {
	router := mux.NewRouter()
	db, err = gorm.Open("postgres", "host=localhost port=5432 user=postgres dbname=cms password=mysecretpassword sslmode=disable")
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()
	db.AutoMigrate(&User{}, &Article{})
	router.HandleFunc("/users", addUser).Methods("POST")
	// router.HandleFunc("/user/{username}", getUser).Methods("GET")
	router.HandleFunc("/user", loginUser).Methods("POST")
	handler := cors.Default().Handler(router)
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func addUser(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	// validation
	if user.Username == "" {
		errorText := Error{Code: "MODLUSR004", Message: "Username is required"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if user.Name == "" {
		errorText := Error{Code: "MODLUSR001", Message: "Name is required"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if user.Password == "" {
		errorText := Error{Code: "MODLUSR002", Message: "Password is required"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Contenet-Type", "application/json")
		w.Write(js)
		return
	}
	if user.Email == "" {
		errorText := Error{Code: "MODLUSR003", Message: "Email is required"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "applicaton/json")
		w.Write(js)
		return
	}
	match, _ := regexp.MatchString("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$", user.Email)
	if !match {
		errorText := Error{Code: "MODLIUSR004", Message: "Enter email in valid format"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	// validation ends

	// Check if username or email is already used or not
	var dupUserUsername User
	var dupUserEmail User
	db.Where(&User{Username: user.Username}).Find(&dupUserUsername)
	db.Where(&User{Email: user.Email}).Find(&dupUserEmail)
	if dupUserUsername.Username != "" {
		errorText := Error{Code: "DBDUPLUSRNME", Message: "Username is already present"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if dupUserEmail.Email != "" {
		errorText := Error{Code: "DBDUPLEMAIL", Message: "Email is already registerd"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	// End of duplication check
	password, err := HashPassword(user.Password)
	if err != nil {
		errorText := Error{Code: "BCRYPTERR", Message: "Internal Server Error Occured"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	uuidString, err := uuid.NewV4()
	if err != nil {
		errorText := Error{Code: "UUIDERR", Message: "Internal Server Error Occured"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	user.Password = password
	user.ID = uuidString.String()
	db.Create(&user)
	json.NewEncoder(w).Encode(&user)
}

// func getUser(w http.ResponseWriter, r *http.Request) {
// 	params := mux.Vars(r)
// 	var user User
// 	var loginUser User
// 	json.NewEncoder(w).Encode(&user)
// 	db.Where(&User{Username: user.Username}).Find(&loginUser)
// 	if CheckPasswordHash(user.Password, loginUser.Password) {
// 		token := Token{Token: "Ok"}
// 		js, _ := json.Marshal(token)
// 		w.Header().Set("Content-Type", "application/json")
// 		w.Write(js)
// 		return
// 	}
// }

func loginUser(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	var loginUser User
	db.Where(&User{Username: user.Username}).Find(&loginUser)
	if CheckPasswordHash(user.Password, loginUser.Password) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": loginUser.Username,
			"password": loginUser.Password,
			"email":    loginUser.Email,
		})
		secret := "secretskylab"
		tokenString, err := token.SignedString(secret)
		tokenRes := Token{Token: tokenString}
		fmt.Print("Token:" + tokenString + "err:" + err)
		js, _ := json.Marshal(tokenRes)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	} else {
		errorText := Error{Code: "AUTHERRLOGIN", Message: "Username or password is not valid"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
