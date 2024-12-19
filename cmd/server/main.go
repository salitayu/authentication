package main

import (
	"authentication/authtools"
	"authentication/models"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"strconv"
	"time"
)

type Env struct {
	loginmodel models.LoginModel
	cache      authtools.RedisClient
}

func main() {
	err := godotenv.Load("local.env")
	if err != nil {
		log.Fatalf("An error occured. Err: %s", err)
	}
	host := "localhost"
	port := "54321"
	user := "postgres"
	pass := "tan"
	dbname := "postgresauthentication"
	newport, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal(err)
	}
	conn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, newport, user, pass, dbname)
	db, err := sql.Open("postgres", conn)
	fmt.Println("conn ", conn)
	if err != nil {
		log.Fatal(err)
	}
	redisConn, err := authtools.ConnectRedis()
	if err != nil {
		panic(err)
	}
	env := &Env{
		loginmodel: models.LoginModel{DB: db},
		cache:      authtools.RedisClient{Conn: redisConn},
	}
	headersOk := handlers.AllowedHeaders([]string{"Content-Type", "Content-Length", "Accept", "Accept-Encoding", "X-Requested-With", "X-CSRF-Token", "Set-Cookie", "Authorization"})
	originsOk := handlers.AllowedOrigins([]string{"http://127.0.0.1:3000", "127.0.0.1:3000", "localhost:3000", "http://localhost:3000"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS", "DELETE"})
	allowCreds := handlers.AllowCredentials()
	exposedHeaders := handlers.ExposedHeaders([]string{"Set-Cookie"})
	r := mux.NewRouter()
	http.Handle("/", r)
	r.HandleFunc("/register", env.Register).Methods("POST")
	r.HandleFunc("/login", env.Login).Methods("POST")
	r.HandleFunc("/categories", env.GetCategories).Methods("GET")
	r.HandleFunc("/logout", env.Logout).Methods("POST")
	log.Fatal(http.ListenAndServe(":8080", handlers.CORS(originsOk, headersOk, methodsOk, exposedHeaders, allowCreds)(r)))
}

func (env *Env) Register(w http.ResponseWriter, r *http.Request) {
	// Get User Details from JSON
	var u models.User
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userAdded, err := env.loginmodel.Register(u)
	fmt.Fprintf(w, "%t", userAdded)
	fmt.Fprintf(w, "Added user %s with password %s", u.Username, u.Password)
	if err != nil {
		log.Print(err)
		http.Error(w, http.StatusText(500), 500)
		return
	}
}

func (env *Env) Login(w http.ResponseWriter, r *http.Request) {
	var lc authtools.LoginCredentials
	err := json.NewDecoder(r.Body).Decode(&lc)
	if err != nil {
		fmt.Println("lc")
		fmt.Println(lc)
		http.Error(w, err.Error(), http.StatusBadRequest)
		fmt.Fprintf(w, "Bad Request")
		return
	}
	loginSuccessful, err := env.loginmodel.Login(lc)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Fprintf(w, "Internal Server Error")
		return
	}

	if loginSuccessful {
		sessionToken := env.cache.CreateSession(w, lc)
		json.NewEncoder(w).Encode(map[string]string{"results": sessionToken})
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   "",
			Expires: time.Now(),
		})
		fmt.Fprintf(w, "Invalid Credentials")
	}
}

func (env *Env) GetCategories(w http.ResponseWriter, r *http.Request) {
	responseCode := env.HandleCheck(w, r)
	if responseCode != http.StatusOK {
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"results": "tech"})
}

func (env *Env) Refresh(w http.ResponseWriter, r *http.Request) {
	env.cache.RefreshSession(w, r)
}

func (env *Env) Logout(w http.ResponseWriter, r *http.Request) {
	responseCode := env.HandleCheck(w, r)
	if responseCode != http.StatusOK {
		return
	}
	env.cache.RemoveSession(w, r)
}

func (env *Env) HandleCheck(w http.ResponseWriter, r *http.Request) int {
	loggedIn := env.cache.CheckSession(w, r)
	fmt.Println("logged in ", loggedIn)

	for _, c := range r.Cookies() {
		fmt.Println("allCookies", c)
	}

	if loggedIn != http.StatusOK {
		response := map[string]int{"Login returned code": loggedIn}
		json.NewEncoder(w).Encode(response)
		return loggedIn
	}
	return loggedIn
}

func (env *Env) Handle(w http.ResponseWriter, r *http.Request) {
	responseCode := env.HandleCheck(w, r)
	if responseCode != http.StatusOK {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"results": "logged in"})
}
