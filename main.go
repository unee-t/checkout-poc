package main

import (
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/apex/log"
	jsonloghandler "github.com/apex/log/handlers/json"
	"github.com/apex/log/handlers/text"
	"github.com/gorilla/mux"
)

var views = template.Must(template.ParseGlob("templates/*.html"))

func init() {
	if os.Getenv("UP_STAGE") != "" {
		log.SetHandler(jsonloghandler.Default)
	} else {
		log.SetHandler(text.Default)
	}
}

func main() {
	addr := ":" + os.Getenv("PORT")
	app := mux.NewRouter()
	app.HandleFunc("/", index)
	app.HandleFunc("/logout", deletecookie)
	app.HandleFunc("/login", getlogin).Methods("GET")
	app.HandleFunc("/login", postlogin).Methods("POST")

	if err := http.ListenAndServe(addr, app); err != nil {
		log.WithError(err).Fatal("error listening")
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	email, err := r.Cookie("email")
	if err != nil || email.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	views.ExecuteTemplate(w, "index.html", struct {
		Email string
	}{
		Email: email.Value,
	})
}

func getlogin(w http.ResponseWriter, r *http.Request) {
	views.ExecuteTemplate(w, "login.html", nil)
}

func postlogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	http.SetCookie(w, &http.Cookie{
		Name:  "email",
		Value: email,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func deletecookie(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{
		Name:     "email",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}

	http.SetCookie(w, c)
	http.Redirect(w, r, "/login", http.StatusFound)
}
