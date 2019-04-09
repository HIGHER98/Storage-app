package main

//mysql -u root -p
//StorageGo
//password1234

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

/* NOT USED
type User struct {
	Uname  string `json:"Username"`
	Secret []byte `json:"Password"`
}

type Session struct {
	Uname  string
	Cookie http.Cookie
}
*/

//Map every cookie to a client. Get username from cookie and thus get access to DB to retrieve files

//var map[http.Cookie.Value]username
var cookiemap map[string]string

const dir = "/home/higher/Documents/golang/src/Third Year TCD/Storage app/html_files/user_files/"

func init() {
	cookiemap = make(map[string]string)
}

func dbConn() (db *sql.DB) {
	dbDriver := "mysql"
	dbUsername := "storageGo"
	dbPassword := "password1234"
	dbName := "StorageApp"
	db, err := sql.Open(dbDriver, dbUsername+":"+dbPassword+"@tcp(127.0.0.1:3306)/"+dbName)
	if err != nil {
		panic(err.Error())
	}
	return db
}

type GetSecGroup struct {
	username          string
	security_group_id int
	file_name         string
	file_path         string
	encryption_key    string
}

func getSecGroup(username string) GetSecGroup {
	var sec GetSecGroup
	db := dbConn()
	defer db.Close()
	//Prepare query and execute it
	//SELECT * FROM StorageApp.user_files_view where username = 'usernamegoeshere';
	query, err := db.Query("SELECT * FROM StorageApp.user_files_view WHERE username=?", username)
	if err != nil {
		fmt.Println("Error: ", err)
		return sec
	}
	for query.Next() {
		err = query.Scan(&sec.username, &sec.security_group_id,
			&sec.file_name, &sec.file_path, &sec.encryption_key)
		if err != nil {
			fmt.Println("Error scanning database values: ", err)
		}
	}
	return sec
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {

	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return plaintext
}

func encryptFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encrypt(data, passphrase))
}

func decryptFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	return decrypt(data, passphrase)
}

//TODO Get a working version of the below. In the meantime I will use getSecGroup
/*
func getSecurityGroup(username string) ([]GetSecGroup, int) {
	var sec []GetSecGroup
	i := -1
	db := dbConn()
	defer db.Close()
	//Prepare query and execute it
	//SELECT * FROM StorageApp.user_files_view where username = 'usernamegoeshere';
	query, err := db.Query("SELECT * FROM StorageApp.user_files_view WHERE username=?", username)
	if err != nil {
		fmt.Println("Error: ", err)
		return sec, i
	}
	for query.Next() {
		i++
		err = query.Scan(&sec[i].username, &sec[i].security_group_id,
			&sec[i].file_name, &sec[i].file_path, &sec[i].encryption_key)
		if err != nil {
			fmt.Println("Error scanning database values: ", err)
		}
	}
	//If there were multiple lines returned
	return sec, i
}*/

//redirect ensures a https connection
func redirect(w http.ResponseWriter, r *http.Request) {
	// remove/add not default ports from r.Host
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	log.Printf("redirect to: %s", target)
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

func authViewHandler(w http.ResponseWriter, r *http.Request) {
	//Authenticated user
	session, _ := r.Cookie("session_token") //Error condition already checked before this function
	user := cookiemap[session.Value]
	fmt.Fprint(w, "Hello ", user)
	//Make gohtml template to show files based on a query to DB
	//Make option to upload file which calls /upload
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	//Check if the request has the correct cookies, if not then no connection
	session, err := r.Cookie("session_token")
	if err == http.ErrNoCookie {
		http.Error(w, http.StatusText(403), http.StatusForbidden)
		return
	}
	if cookiemap[session.Value] != "" {
		fmt.Println("Redirecting to authViewHanlder")
		//newUrl := "/view/" + cookiemap[session.Value]
		authViewHandler(w, r)
		//http.Redirect(w, r, newUrl, http.StatusSeeOther) //Not working for some reason
		//		fmt.Fprint(w, "Hello ", cookiemap[session.Value], ".\nHere are your files")
		//		fmt.Println("The user associated with this account is : ", cookiemap[session.Value])
		return

	} else {
		fmt.Fprint(w, "<!DOCTYPE HTML><html><p>You are not authorized to log in. Click <a href=\"https://localhost:12345/\">here</a> to log in.</p></html>")
		return
	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	//Check that the user is logged in
	session, cookieErr := r.Cookie("session_token")
	if cookieErr == http.ErrNoCookie {
		http.Error(w, http.StatusText(403)+". Try logging in first.", http.StatusForbidden)
		return
	}
	if cookiemap[session.Value] == "" {
		http.Error(w, http.StatusText(403), http.StatusForbidden)
		return
	}
	secGroup := getSecGroup(cookiemap[session.Value])
	if secGroup.security_group_id != 0 {
		//Add security group
	}
	files, err := ioutil.ReadDir("./" + string(secGroup.security_group_id) + "/")
	if err != nil {
		log.Fatal(err)
	}
	var filesList string
	for _, f := range files {
		filesList += f.Name()
	}
	fmt.Fprint(w, "Here are the files in your security group", filesList)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "./html_files/upload.html")
		return
	} else if r.Method == http.MethodPost {
		//Check that the user is logged in
		session, cookieErr := r.Cookie("session_token")
		if cookieErr == http.ErrNoCookie {
			http.Error(w, http.StatusText(403)+". Try logging in first.", http.StatusForbidden)
			return
		}
		if cookiemap[session.Value] == "" {
			http.Error(w, http.StatusText(403), http.StatusForbidden)
			return
		}
		//Get the user's security group
		/*
			sec, numberOfSecGroups := getSecurityGroup(cookiemap[session.Value])
			if numberOfSecGroups > 0 {
				fmt.Fprint(w, "<!DOCTYPE html><html><p>You are in a number of security groups. This means files have been shared with you.</p></html>")
			} else if numberOfSecGroups < 0 {
				fmt.Fprint(w, "You are not in any security groups... I'll make one for you now")
			} else {
				fmt.Fprint(w, "You are in one security group. I'll add the file to that one")
			}*/
		sec := getSecGroup(cookiemap[session.Value])
		fmt.Println("This user belongs to security group ", sec.security_group_id)

		//File will be uploaded here
		file := r.PostFormValue("file1")

		//uploaded is the uploaded file
		uploaded, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Println("File reading error. Error: ", err)
			http.Error(w, http.StatusText(500), http.StatusInternalServerError)
			return
		}
		//Encryption on the file
		//Can't encrypt with RSA as RSA only encrypts data smaller than the key length
		//Encrypt file with aes cipher
		//Write key to security_groups table
		//Write file to memory
		// ./user_files/security_group/

		//Create a file in ./user_file/sec/
		encryptFile("./user_files/"+string(sec.security_group_id), uploaded, cookiemap[session.Value])
		fmt.Fprintf(w, "<!DOCTYPE html><html><p><a href=\"https://localhost:12345/download\"</p></html>")
	} else {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}

}

//Adds new users to the database
func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "./html_files/Signup.html")
		return
	}
	if r.Method != http.MethodPost {
		fmt.Println("Not a post request")
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	username := r.PostFormValue("uname")
	password := r.PostFormValue("psw")

	secret, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		fmt.Println("Error encyrpting users password")
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	db := dbConn()
	defer db.Close()

	//Check if the user already exists
	var u string
	erroring := db.QueryRow("SELECT * FROM Users WHERE Username = ?", username).Scan(&u)
	if erroring != sql.ErrNoRows {
		http.Error(w, http.StatusText(500)+". That username is taken.", http.StatusInternalServerError)
		return
	}
	if username == u {
		http.Error(w, http.StatusText(406)+". That username is already taken. Try another one", http.StatusNotAcceptable)
		return
	}
	//Signup user
	// Prepare statement for inserting data
	insert, err := db.Prepare("INSERT INTO Users VALUES(?, ?)") // ? = placeholder
	if err != nil {
		fmt.Println("Error inserting into database\ndb: \t", db, "\nError: \t", err)
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	defer insert.Close() // Close the statement after updating the database
	_, err = insert.Exec(username, secret)
	if err != nil {
		fmt.Println("err: ", err)
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "<!DOCTYPE HTML><html><p>Sucessfuly signed up! Click <a href=\"https://localhost:12345/\">here</a> to sign in.</p></html>")
}

//Authenticates users using bcyrpt to hash and salt passwords
func authenticateHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Authenticating....")
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	username := r.PostFormValue("uname")
	password := r.PostFormValue("psw")
	db := dbConn()
	defer db.Close()

	var u []byte
	//Prepare statement for query
	erroring := db.QueryRow("SELECT Password FROM Users WHERE Username=?", username).Scan(&u)
	if erroring != nil {
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	err := bcrypt.CompareHashAndPassword(u, []byte(password))
	if err != nil {
		fmt.Println("Error authenticating password. Error: ", err)
		http.Error(w, http.StatusText(403), http.StatusForbidden)
		return
	}

	//Cookie stuff
	sessionToken, er := uuid.NewV4()
	if er != nil {
		http.Error(w, http.StatusText(500), http.StatusInternalServerError)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken.String(),
		Expires: time.Now().Add(120 * time.Second),
	})
	//Associate uuid with username
	cookiemap[sessionToken.String()] = username
	//http.Redirect(w, r, "https://localhost:12345/signup/Signup.html", http.StatusAccepted)
	fmt.Fprint(w, "<!DOCTYPE HTML><html><p>Welcome back ", username, "!</p><p>Click <a href=\"https://localhost:12345/view/\">here</a> to view your files.</p><p>Click <a href=\"https://localhost:12345/upload\">here<a> to upload a file.</p></html>")
}

//var validPath = regexp.MustCompile("^/")
///var validPath = regexp.MustCompile("^/(view|upload|download|signup|)/([A-Za-z0-9]*)$")

func makeHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		/*m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}*/
		fn(w, r)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./html_files/index.html")
}
func main() {
	go http.ListenAndServe(":12345", makeHandler(redirect))
	http.Handle("/", makeHandler(index))
	http.HandleFunc("/signup", makeHandler(signupHandler))
	http.HandleFunc("/authenticate", makeHandler(authenticateHandler))
	http.HandleFunc("/view/{.*}", makeHandler(authViewHandler))
	http.HandleFunc("/view/", makeHandler(viewHandler))
	http.HandleFunc("/download/", makeHandler(downloadHandler))
	http.HandleFunc("/upload", makeHandler(uploadHandler))
	http.Handle("/favicon.ico", http.NotFoundHandler())
	log.Fatal(http.ListenAndServeTLS(":12345", "cert.pem", "key.pem", nil))
}
