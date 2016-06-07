package main

import (
	"fmt"
	"os"
	"github.com/ziutek/mymysql/mysql"
	_ "github.com/ziutek/mymysql/thrsafe"
	//_ "github.com/ziutek/mymysql/native"
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

func checkedResult(rows []mysql.Row, res mysql.Result, err error) ([]mysql.Row, mysql.Result) {
	checkError(err)
	return rows, res
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

	fmt.Printf("Connect to %s:%s... ", proto, addr)
	checkError(db.Connect())
	printOK()

	fmt.Print("Drop A table if exists... ")
	_, err := db.Start("drop table A")
	if err == nil {
		printOK()
	} else if e, ok := err.(*mysql.Error); ok {
		// Error from MySQL server
		fmt.Println(e)
	} else {
		checkError(err)
	}

	fmt.Print("Create A table... ")
	_, err = db.Start("create table A (name varchar(9), number int) engine=InnoDB")
	checkError(err)
	printOK()

	fmt.Print("Prepare insert statement... ")
	ins, err := db.Prepare("insert A values (?, ?)")
	checkError(err)
	printOK()

	fmt.Print("Prepare select statement... ")
	sel, err := db.Prepare("select * from A")
	checkError(err)
	printOK()

	fmt.Print("Begining a new transaction... ")
	tr, err := db.Begin()
	checkError(err)
	printOK()

	tr_ins := tr.Do(ins)

	fmt.Print("Performing two inserts... ")
	_, err = tr_ins.Run("jeden", 1)
	checkError(err)
	_, err = tr_ins.Run("dwa", 2)
	checkError(err)
	printOK()

	fmt.Print("Commit the transaction... ")
	checkError(tr.Commit())
	printOK()

	fmt.Print("Begining a new transaction... ")
	tr, err = db.Begin()
	checkError(err)
	printOK()

	fmt.Print("Performing one insert... ")
	_, err = tr.Do(ins).Run("trzy", 3)
	checkError(err)
	printOK()

	fmt.Print("Rollback the transaction... ")
	checkError(tr.Rollback())
	printOK()

	fmt.Println("Select from A... ")
	rows, res := checkedResult(sel.Exec())
	name := res.Map("name")
	number := res.Map("number")
	for ii, row := range rows {
		fmt.Printf("%d: %-10s %-8d\n", ii, row[name], row[number])
	}

	fmt.Print("Remove A... ")
	checkedResult(db.Query("drop table A"))
	printOK()

	fmt.Print("Close connection... ")
	checkError(db.Close())
	printOK()
}
