package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
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
	router.HandleFunc("/user/{username}", getUser).Methods("GET")
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
	tokenString, err := GenerateJWT(user)
	token := Token{Token: tokenString}
	js, _ := json.Marshal(token)
	if err != nil {
		errorText := Error{Code: "AUTHERRTOKEN", Message: "Internal server error"}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var user User
	db.Where(&User{Username: params["username"]}).Find(&user)
	if len(user.ID) < 1 {
		errorText := Error{Code: "USERNOTFND", Message: "No user exists with username " + params["username"]}
		js, _ := json.Marshal(errorText)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&user)
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	var loginUser User
	db.Where(&User{Username: user.Username}).Find(&loginUser)
	if CheckPasswordHash(user.Password, loginUser.Password) {
		tokenString, err := GenerateJWT(loginUser)
		token := Token{Token: tokenString}
		js, _ := json.Marshal(token)
		if err != nil {
			errorText := Error{Code: "AUTHERRTOKEN", Message: "Internal server error"}
			js, _ := json.Marshal(errorText)
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}
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

func GenerateJWT(user User) (string, error) {
	var mySigningKey = []byte("SUPERSECRET")
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	fmt.Println(user)

	claims["authorized"] = true
	claims["name"] = user.Name
	claims["email"] = user.Email
	claims["username"] = user.Username
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		fmt.Errorf("Something went wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}
