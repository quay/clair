package main

import (
	"os"
	"fmt"
	"time"
	"github.com/ziutek/mymysql/autorc"
	_ "github.com/ziutek/mymysql/thrsafe"
)

func main() {
	user := "testuser"
	passwd := "TestPasswd9"
	dbname := "test"
	//conn := []string{"unix", "", "/var/run/mysqld/mysqld.sock"}
	conn := []string{"tcp", "", "127.0.0.1:3306"}

	c := autorc.New(conn[0], conn[1], conn[2], user, passwd)

	// Register initialisation commands
	c.Raw.Register("set names utf8")

	// my is in unconnected state
	checkErr(c.Use(dbname))

	// Now we ar connected - disconnect
	c.Raw.Close()

	// Drop test table if exists
	_, _, err := c.Query("drop table R")

	fmt.Println("You may restart MySQL sererr or down the network interface.")
	sec := 9
	fmt.Printf("Waiting %ds...", sec)
	for sec--; sec >= 0; sec-- {
		time.Sleep(1e9)
		fmt.Printf("\b\b\b\b\b%ds...", sec)
	}
	fmt.Println()

	// Create table
	_, _, err = c.Query(
		"create table R (id int primary key, name varchar(20))",
	)
	checkErr(err)

	// Kill the connection
	_, _, err = c.Query("kill %d", c.Raw.ThreadId())
	checkErr(err)

	// Prepare insert statement
	ins, err := c.Prepare("insert R values (?,  ?)")
	checkErr(err)

	// Kill the connection
	_, _, err = c.Query("kill %d", c.Raw.ThreadId())
	checkErr(err)

	// Bind insert parameters
	ins.Raw.Bind(1, "jeden")
	// Insert into table
	_, _, err = ins.Exec()
	checkErr(err)

	// Kill the connection
	_, _, err = c.Query("kill %d", c.Raw.ThreadId())
	checkErr(err)

	// Bind insert parameters
	ins.Raw.Bind(2, "dwa")
	// Insert into table
	_, _, err = ins.Exec()
	checkErr(err)

	// Kill the connection
	_, _, err = c.Query("kill %d", c.Raw.ThreadId())
	checkErr(err)

	// Select from table
	rows, res, err := c.Query("select * from R")
	checkErr(err)
	id := res.Map("id")
	name := res.Map("name")
	if len(rows) != 2 ||
		rows[0].Int(id) != 1 || rows[0].Str(name) != "jeden" ||
		rows[1].Int(id) != 2 || rows[1].Str(name) != "dwa" {
		fmt.Println("Bad result")
	}

	// Kill the connection
	_, _, err = c.Query("kill %d", c.Raw.ThreadId())
	checkErr(err)

	// Drop table
	_, _, err = c.Query("drop table R")
	checkErr(err)

	// Disconnect
	c.Raw.Close()

}

func checkErr(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
