package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"

	"github.com/R1m7PY/authorization/settings"
	_ "github.com/go-sql-driver/mysql"
)

// Структура для форм авторизации и регистрации
type User struct {
	id       int
	login    string
	password string
}

// Хэшируем пароль в Md5
func GetMd5(text string) string {
	h := md5.New()
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

func registrHandler(writer http.ResponseWriter, request *http.Request) { // страница регистрации
	html, err := template.ParseFiles("templates/registr.html")
	if err != nil {
		log.Println(err)
	}

	err = html.Execute(writer, nil)
	if err != nil {
		log.Println(err)
	}
}

func registrregHandler(writer http.ResponseWriter, request *http.Request) { // обработка формы регистрации
	user := User{
		login:    request.FormValue("login"),
		password: GetMd5(request.FormValue("password")),
	}

	db, err := sql.Open("mysql", settings.DB_AUTH)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()

	answer, err := db.Query("select * from authorization.users where login=?", user.login)
	if err != nil {
		log.Println(err)
	}

	// Метод Next возвращает true, если есть следующая строка и false, если нет
	// С помощью возвращаемой bool переменной мы проверяем уникальность нового логина
	if answer.Next() {
		_, err := writer.Write([]byte("a user with this username already exists"))
		if err != nil {
			log.Println(err)
		}
	} else {
		result, err := db.Exec("insert into authorization.users (login, password) values (?, ?)", user.login, user.password)
		if err != nil {
			log.Println(err)
		} else {
			LastInsertId, _ := result.LastInsertId()
			RowsAffected, _ := result.RowsAffected()
			log.Printf("LastInsertId: %d, RowsAffected: %d\n", LastInsertId, RowsAffected)
			if err != nil {
				log.Println(err)
			}
			http.Redirect(writer, request, "/login", http.StatusFound)
		}
	}

}

func loginHandler(writer http.ResponseWriter, request *http.Request) { // страница авторизации
	html, err := template.ParseFiles("templates/login.html")
	if err != nil {
		log.Println(err)
	}

	err = html.Execute(writer, nil)
	if err != nil {
		log.Println(err)
	}
}

func loginregHandler(writer http.ResponseWriter, request *http.Request) { // обработка формы авторизации
	user := User{
		login:    request.FormValue("login"),
		password: GetMd5(request.FormValue("password")),
	}

	db, err := sql.Open("mysql", settings.DB_AUTH)
	if err != nil {
		log.Println(err)
	}
	defer db.Close()

	answer, err := db.Query("select * from authorization.users where login=?", user.login)
	if err != nil {
		log.Println(err)
	}

	if answer.Next() {
		var reguser User
		answer.Scan(&reguser.id, &reguser.login, &reguser.password)
		if user.password == reguser.password {
			_, err := writer.Write([]byte("you are authorized"))
			if err != nil {
				log.Println(err)
			}
		} else {
			_, err := writer.Write([]byte("invalid password"))
			if err != nil {
				log.Println(err)
			}
		}
	} else {
		_, err := writer.Write([]byte("there is no user with this username"))
		if err != nil {
			log.Println(err)
		}
	}
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/login/reg", loginregHandler)
	http.HandleFunc("/registr", registrHandler)
	http.HandleFunc("/registr/reg", registrregHandler)

	err := http.ListenAndServe("127.0.0.1:8080", nil)
	log.Fatal(err)
}
