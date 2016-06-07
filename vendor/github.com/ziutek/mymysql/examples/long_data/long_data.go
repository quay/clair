// This example reads URL from stdin and retrieve its content directly to
// database using SendLongData method
package main

import (
	"os"
	"fmt"
	"strings"
	"net/http"
	"github.com/ziutek/mymysql/mysql"
	_ "github.com/ziutek/mymysql/thrsafe"
)

func printOK() {
	fmt.Println("OK")
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	user := "testuser"
	pass := "TestPasswd9"
	dbname := "test"
	//proto  := "unix"
	//addr   := "/var/run/mysqld/mysqld.sock"
	proto := "tcp"
	addr := "127.0.0.1:3306"

	db := mysql.New(proto, "", addr, user, pass, dbname)
	//db.Debug = true

	fmt.Printf("Connect to %s:%s... ", proto, addr)
	checkError(db.Connect())
	printOK()

	fmt.Print("Drop 'web' table if exists... ")
	_, err := db.Start("DROP TABLE web")
	if err == nil {
		printOK()
	} else if e, ok := err.(*mysql.Error); ok {
		// Error from MySQL server
		fmt.Println(e)
	} else {
		checkError(err)
	}

	fmt.Print("Create 'web' table... ")
	_, err = db.Start("CREATE TABLE web (url VARCHAR(80), content LONGBLOB)")
	checkError(err)
	printOK()

	fmt.Print("Prepare insert statement... ")
	ins, err := db.Prepare("INSERT INTO web VALUES (?, ?)")
	checkError(err)
	printOK()

	fmt.Print("Prepare select statement... ")
	sel, err := db.Prepare("SELECT url, OCTET_LENGTH(content) FROM web")
	checkError(err)
	printOK()

	var url string

	fmt.Print("Bind insert parameters... ")
	ins.Bind(&url, []byte(nil))
	printOK()

	fmt.Println()
	for {
		url = ""
		fmt.Print("Please enter an URL (blank line terminates input): ")
		fmt.Scanln(&url)
		if len(url) == 0 {
			break
		}
		if !strings.Contains(url, "://") {
			url = "http://" + url
		}
		http_res, err := http.Get(url)
		if err != nil {
			fmt.Println(err)
			continue
		}
		// Retrieve response directly into database. Use 8 kB buffer.
		checkError(ins.SendLongData(1, http_res.Body, 8192))
		_, err = ins.Run()
		checkError(err)
	}
	fmt.Println()

	fmt.Print("Select from 'web' table... ")
	rows, res, err := sel.Exec()
	checkError(err)
	printOK()

	// Print fields names
	fmt.Println()
	for _, field := range res.Fields() {
		fmt.Printf("%-38s ", field.Name)
	}
	fmt.Println()
	fmt.Println("------------------------------------------------------------")

	// Print result
	for _, row := range rows {
		for ii, col := range row {
			if col == nil {
				fmt.Print("%-38s ", "NULL")
			} else {
				fmt.Printf("%-38s ", row.Bin(ii))
			}
		}
		fmt.Println()
	}
	fmt.Println()

	fmt.Print("Hit ENTER to exit ")
	fmt.Scanln()

	fmt.Print("Remove 'web' table... ")
	_, err = db.Start("DROP TABLE web")
	checkError(err)
	printOK()

	fmt.Print("Close connection... ")
	checkError(db.Close())
	printOK()
}
