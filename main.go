package main

import(
	"net/http"
	"log"
)

func handler(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-type", "text/plain")
	w.Write([]byte("This is my server"))
}

func main(){
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServeTLS(":12345", "cert.pem", "key.pem", nil))

}
