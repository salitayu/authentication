package models

import (
	"authentication/authtools"
	"database/sql"
	"fmt"
)

type LoginModel struct {
	DB *sql.DB
}

type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	IsGuest     bool   `json:"is_guest" db:"is_guest"`
	IsSuperuser bool   `json:"is_superuser" db:"is_superuser"`
	Username    string `json:"username" db:"username"`
	FirstName   string `json:"firstname" db:"firstname"`
	LastName    string `json:"lastname" db:"lastname"`
	Email       string `json:"email" db:"email"`
	Password    string `json:"password" db:"password"`
}

func (lm LoginModel) Register(u User) (bool, error) {
	p := &authtools.AuthParams{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	encodedHash, err := authtools.GenerateFromPassword(u.Password, p)
	if err != nil {
		return false, err
	}
	_, err = lm.DB.Exec("INSERT INTO users (is_guest, is_superuser, username, firstname, lastname, email, password) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		u.IsGuest,
		u.IsSuperuser,
		u.Username,
		u.FirstName,
		u.LastName,
		u.Email,
		encodedHash)
	if err != nil {
		return false, err
	}
	fmt.Println("user")
	fmt.Println(u)
	return true, nil
}

func (lm LoginModel) Login(creds authtools.LoginCredentials) (bool, error) {
	var password string
	row := lm.DB.QueryRow("SELECT password FROM users WHERE username = $1", creds.Username)
	if err := row.Scan(&password); err != nil {
		if err == sql.ErrNoRows {
			return false, err
		}
	}
	validCreds, err := authtools.ComparePasswordAndHash(creds.Password, password)
	if err != nil {
		return false, err
	}
	return validCreds, nil
}
