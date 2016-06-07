package main

import (
	"database/sql"
	"fmt"
	_ "github.com/ziutek/mymysql/godrv" // Go driver for database/sql package
	"log"
)

func main() {
	db, err := sql.Open("mymysql", "tcp:127.0.0.1:3306*mydb/username/passw0rd")
	if err != nil {
		log.Fatal(err)
	}

	id := 1
	var query = "SELECT email from users WHERE id = ?"

	rows, err := db.Query(query, id)
	if err != nil {
		log.Fatal(err)
	}

	var email string
	for rows.Next() {
		if err := rows.Scan(&email); err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Email address: %s\n", email)

	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}
