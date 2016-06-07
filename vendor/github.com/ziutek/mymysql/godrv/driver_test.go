package godrv

import (
	"database/sql"
	"fmt"
	"github.com/ziutek/mymysql/mysql"
	"testing"
	"time"
)

func init() {
	Register("set names utf8")
}

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
}
func checkErrId(t *testing.T, err error, rid, eid int64) {
	checkErr(t, err)
	if rid != eid {
		t.Fatal("res.LastInsertId() ==", rid, "but should be", eid)
	}
}

func TestAll(t *testing.T) {
	data := []string{"jeden", "dwa", "trzy"}

	db, err := sql.Open("mymysql", "test/testuser/TestPasswd9")
	checkErr(t, err)
	defer db.Close()
	defer db.Exec("DROP TABLE go")

	db.Exec("DROP TABLE go")

	_, err = db.Exec(
		`CREATE TABLE go (
			id  INT(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
			txt TEXT,
			n   BIGINT
		) ENGINE=InnoDB`)
	checkErr(t, err)

	ins, err := db.Prepare("INSERT go SET txt=?, n=?")
	checkErr(t, err)

	tx, err := db.Begin()
	checkErr(t, err)

	res, err := ins.Exec(data[0], 0)
	checkErr(t, err)
	id, err := res.LastInsertId()
	checkErrId(t, err, id, 1)

	res, err = ins.Exec(data[1], 1)
	checkErr(t, err)
	id, err = res.LastInsertId()
	checkErrId(t, err, id, 2)

	checkErr(t, tx.Commit())

	tx, err = db.Begin()
	checkErr(t, err)

	res, err = tx.Exec("INSERT go SET txt=?, n=?", "cztery", 3)
	checkErr(t, err)
	id, err = res.LastInsertId()
	checkErrId(t, err, id, 3)

	checkErr(t, tx.Rollback())

	rows, err := db.Query("SELECT * FROM go")
	checkErr(t, err)
	i := 1
	for rows.Next() {
		var (
			id  int
			txt string
			n   int64
		)
		checkErr(t, rows.Scan(&id, &txt, &n))
		if id > len(data) {
			t.Fatal("To many rows in table")
		}
		if id != i || data[i-1] != txt || int64(i-1) != n {
			t.Fatalf("txt[%d] == '%s' != '%s'", id, txt, data[id-1])
		}
		i++
	}
	checkErr(t, rows.Err())

	sel, err := db.Prepare("SELECT * FROM go")
	checkErr(t, err)

	rows, err = sel.Query()
	checkErr(t, err)
	i = 1
	for rows.Next() {
		var (
			id  int
			txt string
			n   int64
		)
		checkErr(t, rows.Scan(&id, &txt, &n))
		if id > len(data) {
			t.Fatal("To many rows in table")
		}
		if id != i || data[i-1] != txt || int64(i-1) != n {
			t.Fatalf("txt[%d] == '%s' != '%s'", id, txt, data[id-1])
		}
		i++
	}
	checkErr(t, rows.Err())

	sql := "select sum(41) as test"
	row := db.QueryRow(sql)
	var vi int64
	checkErr(t, row.Scan(&vi))
	if vi != 41 {
		t.Fatal(sql)
	}
	sql = "select sum(4123232323232) as test"
	row = db.QueryRow(sql)
	var vf float64
	checkErr(t, row.Scan(&vf))
	if vf != 4123232323232 {
		t.Fatal(sql)
	}
}

func TestMediumInt(t *testing.T) {
	db, err := sql.Open("mymysql", "test/testuser/TestPasswd9")
	checkErr(t, err)
	defer db.Exec("DROP TABLE mi")
	defer db.Close()

	db.Exec("DROP TABLE mi")

	_, err = db.Exec(
		`CREATE TABLE mi (
			id INT PRIMARY KEY AUTO_INCREMENT,
			m MEDIUMINT
		)`)
	checkErr(t, err)

	const n = 9

	for i := 0; i < n; i++ {
		_, err = db.Exec("INSERT mi VALUES (0, ?)", i)
		checkErr(t, err)
	}

	rows, err := db.Query("SELECT * FROM mi")
	checkErr(t, err)

	var i int
	for i = 0; rows.Next(); i++ {
		var id, m int
		checkErr(t, rows.Scan(&id, &m))
		if id != i+1 || m != i {
			t.Fatalf("i=%d id=%d m=%d", i, id, m)
		}
	}
	checkErr(t, rows.Err())
	if i != n {
		t.Fatalf("%d rows read, %d expected", i, n)
	}
}

func TestTypes(t *testing.T) {
	db, err := sql.Open("mymysql", "test/testuser/TestPasswd9")
	checkErr(t, err)
	defer db.Close()
	defer db.Exec("DROP TABLE t")

	db.Exec("DROP TABLE t")

	_, err = db.Exec(
		`CREATE TABLE t (
			i INT NOT NULL,
			f DOUBLE NOT NULL, 
			b BOOL NOT NULL,
			s VARCHAR(8) NOT NULL,
			d DATETIME NOT NULL,
			y DATE NOT NULL,
			n INT
		) ENGINE=InnoDB`)
	checkErr(t, err)

	_, err = db.Exec(
		`INSERT t VALUES (
			23, 0.25, true, 'test', '2013-03-06 21:07', '2013-03-19', NULL
		)`,
	)
	checkErr(t, err)
	l, err := time.LoadLocation("Local")
	td := time.Date(2013, 3, 6, 21, 7, 0, 0, l)
	dd := time.Date(2013, 3, 19, 0, 0, 0, 0, l)
	checkErr(t, err)
	_, err = db.Exec(
		"INSERT t VALUES (?, ?, ?, ?, ?, ?)",
		23, 0.25, true, "test", td, dd, nil,
	)

	rows, err := db.Query("SELECT * FROM t")
	checkErr(t, err)
	var (
		i int64
		f float64
		b bool
		s string
		d time.Time
		y time.Time
		n sql.NullInt64
	)

	for rows.Next() {
		checkErr(t, rows.Scan(&i, &f, &b, &s, &d, &y, &n))
		if i != 23 {
			t.Fatal("int64", i)
		}
		if f != 0.25 {
			t.Fatal("float64", f)
		}
		if b != true {
			t.Fatal("bool", b)
		}
		if s != "test" {
			t.Fatal("string", s)
		}
		if d != td {
			t.Fatal("time.Time", d)
		}
		if y != dd {
			t.Fatal("time.Time", y)
		}
		if n.Valid {
			t.Fatal("mysql.NullInt64", n)
		}
	}
}

func TestMultiple(t *testing.T) {
	db, err := sql.Open("mymysql", "test/testuser/TestPasswd9")
	checkErr(t, err)
	defer db.Close()
	defer db.Exec("DROP TABLE t")

	db.Exec("DROP TABLE t")
	_, err = db.Exec(`CREATE TABLE t (
		email       VARCHAR(16),
		password    VARCHAR(16),
		status      VARCHAR(16),
		signup_date DATETIME,
		zipcode     VARCHAR(16),
		fname       VARCHAR(16),
		lname       VARCHAR(16)
	)`)
	checkErr(t, err)

	const shortFormat = "2006-01-02 15:04:05"
	now := time.Now()

	_, err = db.Exec(fmt.Sprintf(`INSERT INTO t (
		email,
		password,
		status,
		signup_date,
		zipcode,
		fname,
		lname
	) VALUES (
		'a@a.com',
		'asdf',
		'unverified',
		'%s',
		'111',
		'asdf',
		'asdf'
	);`, now.Format(mysql.TimeFormat)))
	checkErr(t, err)

	_, err = db.Exec(`INSERT INTO t (
		email,
		password,
		status,
		signup_date,
		zipcode,
		fname,
	    lname
	) VALUES (
      ?, ?, ?, ?, ?, ?, ?
	);`, "a@a.com", "asdf", "unverified", now, "111", "asdf", "asdf")
	checkErr(t, err)

	_, err = db.Exec(`INSERT INTO t (
		email,
		password,
		status,
		signup_date,
		zipcode,
		fname,
	    lname
	) VALUES (
      "a@a.com", 'asdf', ?, ?, ?, ?, 'asdf'
	);`, "unverified", now, "111", "asdf")
	checkErr(t, err)

	rows, err := db.Query("SELECT * FROM t")
	checkErr(t, err)
	var (
		email, password, status, zipcode, fname, lname string
		signup_date                                    time.Time
	)
	n := 0
	for rows.Next() {
		checkErr(t, rows.Scan(
			&email, &password, &status, &signup_date, &zipcode, &fname, &lname,
		))
		if email != "a@a.com" {
			t.Fatal(n, "email:", email)
		}
		if password != "asdf" {
			t.Fatal(n, "password:", password)
		}
		if status != "unverified" {
			t.Fatal(n, "status:", status)

		}
		e := signup_date.Format(mysql.TimeFormat)
		d := signup_date.Format(mysql.TimeFormat)
		if e[:len(shortFormat)] != d[:len(shortFormat)] {
			t.Fatal(n, "signup_date:", d)
		}
		if zipcode != "111" {
			t.Fatal(n, "zipcode:", zipcode)
		}
		if fname != "asdf" {
			t.Fatal(n, "fname:", fname)
		}
		if lname != "asdf" {
			t.Fatal(n, "lname:", lname)
		}
		n++
	}
	if n != 3 {
		t.Fatal("Too short result set")
	}
}
