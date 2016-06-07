package main

import (
	"fmt"
	"os"
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
	checkedResult(db.Query("create table A (name varchar(40), number int)"))
	printOK()

	fmt.Print("Prepare insert statement... ")
	ins, err := db.Prepare("insert A values (?, ?)")
	checkError(err)
	printOK()

	fmt.Print("Prepare select statement... ")
	sel, err := db.Prepare("select * from A where number > ? or number is null")
	checkError(err)
	printOK()

	params := struct {
		txt    *string
		number *int
	}{}

	fmt.Print("Bind insert parameters... ")
	ins.Bind(&params)
	printOK()

	fmt.Print("Insert into A... ")
	for ii := 0; ii < 1000; ii += 100 {
		if ii%500 == 0 {
			// Assign NULL values to the parameters
			params.txt = nil
			params.number = nil
		} else {
			// Modify parameters
			str := fmt.Sprintf("%d*10= %d", ii/100, ii/10)
			params.txt = &str
			params.number = &ii
		}
		// Execute statement with modified data
		_, err = ins.Run()
		checkError(err)
	}
	printOK()

	fmt.Println("Select from A... ")
	rows, res := checkedResult(sel.Exec(0))
	name := res.Map("name")
	number := res.Map("number")
	for ii, row := range rows {
		fmt.Printf(
			"Row: %d\n name:  %-10s {%#v}\n number: %-8d  {%#v}\n", ii,
			"'"+row.Str(name)+"'", row[name],
			row.Int(number), row[number],
		)
	}

	fmt.Print("Remove A... ")
	checkedResult(db.Query("drop table A"))
	printOK()

	fmt.Print("Close connection... ")
	checkError(db.Close())
	printOK()
}
