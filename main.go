package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/minio/minio-go"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/cors"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB
var err error
var minioClient *minio.Client

func main() {

	// minio start
	endpoint := "127.0.0.1:9000"
	accessKeyID := "NPtuYx684U7FIDg97SLL3pU3kzV1n4Yt"
	secretKeyID := "W0Rpu3g06aXBiuAY6ygcZPnzBBlFQV5l"
	useSSL := false

	minioClient, err = minio.New(endpoint, accessKeyID, secretKeyID, useSSL)
	if err != nil {
		log.Fatalln(err)
	}
	// log.Printf("%#v\n", minioClient)
	// minio end

	router := mux.NewRouter()
	db, err = gorm.Open("postgres", "host=localhost port=5432 user=postgres dbname=cms password=mysecretpassword sslmode=disable")
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()
	db.AutoMigrate(&User{}, &Article{}, &MFile{})
	router.HandleFunc("/users", addUser).Methods("POST")
	router.HandleFunc("/user/{username}", getUser).Methods("GET")
	router.HandleFunc("/user", loginUser).Methods("POST")
	router.HandleFunc("/articles", getArticles).Methods("GET")
	router.HandleFunc("/articles/{username}", getArticles).Methods("GET")
	router.HandleFunc("/article/{id}", getArticle).Methods("GET")
	router.HandleFunc("/article", addArticle).Methods("POST")
	router.HandleFunc("/file", uploadFile).Methods("POST")
	router.HandleFunc("/files", getAllFiles).Methods("GET")
	router.HandleFunc("/file/{filename}", getFile).Methods("GET")
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
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if user.Name == "" {
		errorText := Error{Code: "MODLUSR001", Message: "Name is required"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if user.Password == "" {
		errorText := Error{Code: "MODLUSR002", Message: "Password is required"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Contenet-Type", "application/json")
		w.Write(js)
		return
	}
	if user.Email == "" {
		errorText := Error{Code: "MODLUSR003", Message: "Email is required"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "applicaton/json")
		w.Write(js)
		return
	}
	match, _ := regexp.MatchString("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$", user.Email)
	if !match {
		errorText := Error{Code: "MODLIUSR004", Message: "Enter email in valid format"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusBadRequest)
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
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if dupUserEmail.Email != "" {
		errorText := Error{Code: "DBDUPLEMAIL", Message: "Email is already registerd"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	// End of duplication check
	password, err := HashPassword(user.Password)
	if err != nil {
		errorText := Error{Code: "BCRYPTERR", Message: "Internal Server Error Occured"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	uuidString, err := uuid.NewV4()
	if err != nil {
		errorText := Error{Code: "UUIDERR", Message: "Internal Server Error Occured"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
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
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	w.WriteHeader(http.StatusOK)
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
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	w.WriteHeader(http.StatusOK)
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
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	} else {
		errorText := Error{Code: "AUTHERRLOGIN", Message: "Username or password is not valid"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
}

func addArticle(w http.ResponseWriter, r *http.Request) {
	var article Article
	var user User
	json.NewDecoder(r.Body).Decode(&article)
	authHeader := r.Header.Get("Authorization")
	authToken := strings.Split(authHeader, " ")
	token, err := verifyToken(authToken[1])
	if err != nil {
		errorText := Error{Code: "ERRTOKEN", Message: "Internal Server Error Occured"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if token.Valid {
		mapstructure.Decode(token.Claims, &user)
	} else {
		errorText := Error{Code: "ERRAUTH", Message: "Invalid token"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	// Validation
	if article.Title == "" {
		errorText := Error{Code: "MODLARTL001", Message: "Article title is required"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if article.Content == "" {
		errorText := Error{Code: "MODLARTL002", Message: "Article content is required"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if article.Desc == "" {
		errorText := Error{Code: "MODLARTL003", Message: "Article description is required"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	str := EncodeString(string(article.Title + "-" + article.Desc))
	article.Title = article.Title + "-" + str
	article.Title = strings.Replace(article.Title, " ", "-", -1)
	uuidString, err := uuid.NewV4()
	if err != nil {
		errorText := Error{Code: "UUIDERR", Message: "Internal Server Error Occured"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	article.ID = uuidString.String()
	article.Username = user.Username
	db.Create(&article)
	json.NewEncoder(w).Encode(&article)
}

func getArticle(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var article Article
	fmt.Println(params["id"])
	// Don't know whty db.Where(&Article{Title: params["id"]}).Find(&article) is not working
	db.Raw("SELECT * from articles WHERE title = ?", params["id"]).Scan(&article)
	fmt.Println(article)
	if len(article.Title) < 1 {
		errorText := Error{Code: "ARTLNOTFND", Message: "No article such exists"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&article)
}

func getArticles(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var articles []Article
	var user User
	if params["username"] == "" {
		db.Raw("SELECT * FROM articles").Scan(&articles)
	} else if params["username"] == "my-articles" {
		authHeader := r.Header.Get("Authorization")
		authToken := strings.Split(authHeader, " ")
		token, err := verifyToken(authToken[1])
		if err != nil {
			errorText := Error{Code: "ERRTOKEN", Message: "Internal Server Error Occured"}
			js, _ := json.Marshal(errorText)
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}
		if token.Valid {
			mapstructure.Decode(token.Claims, &user)
		} else {
			errorText := Error{Code: "ERRAUTH", Message: "Invalid token"}
			js, _ := json.Marshal(errorText)
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}
		db.Raw("SELECT * FROM articles WHERE username = ?", user.Username).Scan(&articles)
	} else {
		db.Raw("SELECT * FROM articles WHERE username = ?", params["username"]).Scan(&articles)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&articles)
}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	var Buf bytes.Buffer
	var user User
	authHeader := r.Header.Get("Authorization")
	authToken := strings.Split(authHeader, " ")
	token, err := verifyToken(authToken[1])
	if err != nil {
		errorText := Error{Code: "ERRTOKEN", Message: "Internal Server Error Occured"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if token.Valid {
		mapstructure.Decode(token.Claims, &user)
	} else {
		errorText := Error{Code: "ERRAUTH", Message: "Invalid token"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		errorText := Error{Code: "FILEUPLOADERR", Message: "File not found. Check your parameters"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	defer file.Close()
	name := strings.Split(header.Filename, ".")
	fmt.Printf("File name %s\n", name[0])
	io.Copy(&Buf, file)
	err = ioutil.WriteFile(header.Filename, Buf.Bytes(), 0644)
	minioFile, err := os.Open(header.Filename)
	if err != nil {
		errorText := Error{Code: "FILEUPLOADERR", Message: "Internal server error"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	minioFileStat, err := minioFile.Stat()
	defer func() {
		if err := minioFile.Close(); err != nil {
			errorText := Error{Code: "FILEUPLOADERR", Message: "Internal server error"}
			js, _ := json.Marshal(errorText)
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}
	}()
	contentType := strings.Split(minioFile.Name(), ".")[1]
	uploadFile, err := minioClient.PutObject("testbucket", header.Filename, minioFile, minioFileStat.Size(), minio.PutObjectOptions{ContentType: "image/" + contentType})
	fmt.Print(uploadFile)
	if err != nil {
		errorText := Error{Code: "FILEUPLOADERR", Message: "Internal server error"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	data := EncodeString(header.Filename + string(minioFileStat.Size()))
	mFile := &MFile{ID: data, Name: header.Filename, Size: string(minioFileStat.Size()), Username: string(user.Username), Link: "http://localhost:8080/file/" + header.Filename, MinioLink: "https://localhost:9000/" + "testbucket/" + header.Filename}
	db.Create(&mFile)
	os.Remove(header.Filename)
	Buf.Reset()
	// errorText := Error{Code: "FILEUPLOADSUCC-" + strconv.FormatInt(uploadedFile, 10), Message: "File uploaded successfully"}
	js, _ := json.Marshal(mFile)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func getAllFiles(w http.ResponseWriter, r *http.Request) {
	var mfiles []MFile
	var user User
	authHeader := r.Header.Get("Authorization")
	authToken := strings.Split(authHeader, " ")
	token, err := verifyToken(authToken[1])
	if err != nil {
		errorText := Error{Code: "ERRTOKEN", Message: "Internal Server Error Occured"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	if token.Valid {
		mapstructure.Decode(token.Claims, &user)
	} else {
		errorText := Error{Code: "ERRAUTH", Message: "Invalid token"}
		js, _ := json.Marshal(errorText)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
		return
	}
	fmt.Println(user.Username)
	db.Raw("SELECT * FROM m_files WHERE username = ?", string(user.Username)).Scan(&mfiles)
	fmt.Print(mfiles)
	// doneCh := make(chan struct{})

	// defer close(doneCh)

	// isRecursive := true

	// objectCh := minioClient.ListObjectsV2("testbucket", "", isRecursive, doneCh)

	// for object := range objectCh {
	// 	if object.Err != nil {
	// 		fmt.Print(object.Err)
	// 		return
	// 	}
	// 	mfiles = append(mfiles, MFile{Name: object.Key, Size: string(object.Size), Link: "http://localhost:8080/file/" + object.Key})
	// }
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&mfiles)

}

func getFile(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	filename := params["filename"]
	// object, err := minioClient.GetObject("testbucket", filename, minio.GetObjectOptions{})
	err := minioClient.FGetObject("testbucket", filename, filename, minio.GetObjectOptions{})
	if err != nil {
		panic(err)
	}
	file, err := os.Open(filename)
	FileHeader := make([]byte, 512)
	file.Read(FileHeader)
	FileContentType := http.DetectContentType(FileHeader)
	FileStat, _ := file.Stat()
	FileSize := strconv.FormatInt(FileStat.Size(), 10)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", FileContentType)
	w.Header().Set("Content-Length", FileSize)
	file.Seek(0, 0)
	io.Copy(w, file)
	os.Remove(filename)
	return
}

// Miscellaneous functions
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

func verifyToken(authToken string) (*jwt.Token, error) {
	token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte("SUPERSECRET"), nil
	})
	return token, err
}

func EncodeString(str string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(str))
	return encoded
}
