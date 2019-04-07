package main

//mysql -u root -p

//root
//password123

//StorageGo
//password1234

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Uname  string `json:"Username"`
	Secret []byte `json:"Password"`
}

/*
Make handlers for:
	Homepage
	Signup page
	Login page
	Logged in homepage
	View files
	Upload file
	Download file
*/

func viewHandler(w http.ResponseWriter, r *http.Request) {
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {

}

func uploadHandler(w http.ResponseWriter, r *http.Request) {

}

func loginHandler(w http.ResponseWriter, r *http.Request) {

}

//Adds new users to the database
func signupHandler(w http.ResponseWriter, r *http.Request) {
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
	fmt.Fprint(w, "Signed up!")
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
	fmt.Fprintln(w, "Sucessfully authenticated")
}

//Url: https://localhost:12345/view/SHA256_output_of_username
//var validPath = regexp.MustCompile("^/")
///var validPath = regexp.MustCompile("^/(view|upload|download|signup|login|)/([A-Za-z0-9]*)$")

func makeHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		///m := validPath.FindStringSubmatch(r.URL.Path)
		//fmt.Println("m: ", m, "\nvalidPath.FindStringSubmatch(r.URL.Path)", validPath.FindStringSubmatch(r.URL.Path))
		/*if m == nil {
			//			fmt.Println("w: ", w, "\nr: ", r, "\nm: ", m)
			http.NotFound(w, r)
			return
		}*/
		//		fmt.Println("w: ", w, "\nr: ", r, "\nm[2]: ", m[2])

		fn(w, r)
	}
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
func main() {
	http.Handle("/", http.FileServer(http.Dir("./html_files/")))
	// http.RedirectHandler("https://localhost:12345/login", 301))
	http.Handle("/signup/", http.StripPrefix("/signup/", http.FileServer(http.Dir("./html_files/"))))
	http.HandleFunc("/signup", makeHandler(signupHandler))

	http.HandleFunc("/authenticate", makeHandler(authenticateHandler))
	http.HandleFunc("/login/", makeHandler(loginHandler))
	http.HandleFunc("/view/", makeHandler(viewHandler))
	http.HandleFunc("/download/", makeHandler(downloadHandler))
	http.HandleFunc("/upload/", makeHandler(uploadHandler))
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":12345", nil)
	//	log.Fatal(http.ListenAndServeTLS(":12345", "cert.pem", "key.pem", nil))
}
