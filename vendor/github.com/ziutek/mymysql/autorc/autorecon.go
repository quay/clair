// Auto reconnect interface for MyMySQL
package autorc

import (
	"github.com/ziutek/mymysql/mysql"
	"io"
	"log"
	"net"
	"time"
)

// Return true if error is network error or UnexpectedEOF.
func IsNetErr(err error) bool {
	if err == io.ErrUnexpectedEOF {
		return true
	}
	if _, ok := err.(net.Error); ok {
		return true
	}
	if mysqlError, ok := err.(mysql.Error); ok {
		switch mysqlError.Code {
		case mysql.ER_QUERY_INTERRUPTED:
			return true
		case mysql.ER_NET_READ_ERROR:
			return true
		case mysql.ER_NET_READ_INTERRUPTED:
			return true
		case mysql.ER_NET_ERROR_ON_WRITE:
			return true
		case mysql.ER_NET_WRITE_INTERRUPTED:
			return true
		}
	}
	return false
}

type Conn struct {
	Raw mysql.Conn
	// Maximum reconnect retries.
	// Default is 7 which means 1+2+3+4+5+6+7 = 28 seconds before return error
	// (if waiting for error takes no time).
	MaxRetries int

	// Debug logging. You may change it at any time.
	Debug bool
}

func New(proto, laddr, raddr, user, passwd string, db ...string) *Conn {
	return &Conn{
		Raw:        mysql.New(proto, laddr, raddr, user, passwd, db...),
		MaxRetries: 7,
	}
}

func NewFromCF(cfgFile string) (*Conn, map[string]string, error) {
	raw, unk, err := mysql.NewFromCF(cfgFile)
	if err != nil {
		return nil, nil, err
	}
	return &Conn{raw, 7, false}, unk, nil
}

func (c *Conn) Clone() *Conn {
	return &Conn{
		Raw:        c.Raw.Clone(),
		MaxRetries: c.MaxRetries,
		Debug:      c.Debug,
	}
}

func (c *Conn) SetTimeout(timeout time.Duration) {
	c.Raw.SetTimeout(timeout)
}

func (c *Conn) reconnectIfNetErr(nn *int, err *error) {
	for *err != nil && IsNetErr(*err) && *nn <= c.MaxRetries {
		if c.Debug {
			log.Printf("Error: '%s' - reconnecting...", *err)
		}
		time.Sleep(time.Second * time.Duration(*nn))
		*err = c.Raw.Reconnect()
		if c.Debug && *err != nil {
			log.Println("Can't reconnect:", *err)
		}
		*nn++
	}
}

func (c *Conn) connectIfNotConnected() (err error) {
	if c.Raw.IsConnected() {
		return
	}
	err = c.Raw.Connect()
	nn := 0
	c.reconnectIfNetErr(&nn, &err)
	return
}

func (c *Conn) Reconnect() (err error) {
	err = c.Raw.Reconnect()
	nn := 0
	c.reconnectIfNetErr(&nn, &err)
	return
}

func (c *Conn) Register(sql string) {
	c.Raw.Register(sql)
}

func (c *Conn) SetMaxPktSize(new_size int) int {
	return c.Raw.SetMaxPktSize(new_size)
}

// Automatic connect/reconnect/repeat version of Use
func (c *Conn) Use(dbname string) (err error) {
	if err = c.connectIfNotConnected(); err != nil {
		return
	}
	nn := 0
	for {
		if err = c.Raw.Use(dbname); err == nil {
			return
		}
		if c.reconnectIfNetErr(&nn, &err); err != nil {
			return
		}
	}
	panic(nil)
}

// Automatic connect/reconnect/repeat version of Query
func (c *Conn) Query(sql string, params ...interface{}) (rows []mysql.Row, res mysql.Result, err error) {

	if err = c.connectIfNotConnected(); err != nil {
		return
	}
	nn := 0
	for {
		if rows, res, err = c.Raw.Query(sql, params...); err == nil {
			return
		}
		if c.reconnectIfNetErr(&nn, &err); err != nil {
			return
		}
	}
	panic(nil)
}

func (c *Conn) QueryFirst(sql string, params ...interface{}) (row mysql.Row, res mysql.Result, err error) {

	if err = c.connectIfNotConnected(); err != nil {
		return
	}
	nn := 0
	for {
		if row, res, err = c.Raw.QueryFirst(sql, params...); err == nil {
			return
		}
		if c.reconnectIfNetErr(&nn, &err); err != nil {
			return
		}
	}
	panic(nil)
}

func (c *Conn) QueryLast(sql string, params ...interface{}) (row mysql.Row, res mysql.Result, err error) {

	if err = c.connectIfNotConnected(); err != nil {
		return
	}
	nn := 0
	for {
		if row, res, err = c.Raw.QueryLast(sql, params...); err == nil {
			return
		}
		if c.reconnectIfNetErr(&nn, &err); err != nil {
			return
		}
	}
	panic(nil)
}

func (c *Conn) Escape(s string) string {
	return c.Raw.Escape(s)
}

type Stmt struct {
	Raw mysql.Stmt
	con *Conn

	sql string
}

// Prepares statement if it wasn't prepared before
func (c *Conn) PrepareOnce(s *Stmt, sql string) error {
	if s.Raw != nil {
		return nil
	}
	if err := c.connectIfNotConnected(); err != nil {
		return err
	}
	nn := 0
	for {
		var err error
		if s.Raw, err = c.Raw.Prepare(sql); err == nil {
			s.con = c
			return nil
		}
		if c.reconnectIfNetErr(&nn, &err); err != nil {
			return err
		}
	}
	panic(nil)
}

// Automatic connect/reconnect/repeat version of Prepare
func (c *Conn) Prepare(sql string) (*Stmt, error) {
	var s Stmt
	s.sql = sql
	if err := c.PrepareOnce(&s, sql); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Conn) reprepare(stmt *Stmt) error {
	sql := stmt.sql
	stmt.Raw = nil

	return c.PrepareOnce(stmt, sql)
}

// Begin begins a transaction and calls f to complete it .
// If f returns an error and IsNetErr(error) == true it reconnects and calls
// f up to MaxRetries times. If error is of type *mysql.Error it tries rollback
// the transaction.
func (c *Conn) Begin(f func(mysql.Transaction, ...interface{}) error, args ...interface{}) error {
	err := c.connectIfNotConnected()
	if err != nil {
		return err
	}
	nn := 0
	for {
		var tr mysql.Transaction
		if tr, err = c.Raw.Begin(); err == nil {
			if err = f(tr, args...); err == nil {
				return nil
			}
		}
		if c.reconnectIfNetErr(&nn, &err); err != nil {
			if _, ok := err.(*mysql.Error); ok && tr.IsValid() {
				tr.Rollback()
			}
			return err
		}
	}
	panic(nil)
}

func (s *Stmt) Bind(params ...interface{}) {
	s.Raw.Bind(params...)
}

func (s *Stmt) needsRepreparing(err error) bool {
	if mysqlErr, ok := err.(*mysql.Error); ok {
		if mysqlErr.Code == mysql.ER_UNKNOWN_STMT_HANDLER {
			return true
		}
	}

	return false
}

// Automatic connect/reconnect/repeat version of Exec
func (s *Stmt) Exec(params ...interface{}) (rows []mysql.Row, res mysql.Result, err error) {

	if err = s.con.connectIfNotConnected(); err != nil {
		return
	}
	nn := 0
	for {
		if rows, res, err = s.Raw.Exec(params...); err == nil {
			return
		}

		if s.needsRepreparing(err) {
			if s.con.reprepare(s) != nil {
				return
			}

			// Try again
			continue
		}

		if s.con.reconnectIfNetErr(&nn, &err); err != nil {
			return
		}
	}
	panic(nil)
}

func (s *Stmt) ExecFirst(params ...interface{}) (row mysql.Row, res mysql.Result, err error) {

	if err = s.con.connectIfNotConnected(); err != nil {
		return
	}
	nn := 0
	for {
		if row, res, err = s.Raw.ExecFirst(params...); err == nil {
			return
		}

		if s.needsRepreparing(err) {
			if s.con.reprepare(s) != nil {
				return
			}

			// Try again
			continue
		}

		if s.con.reconnectIfNetErr(&nn, &err); err != nil {
			return
		}
	}
	panic(nil)
}

func (s *Stmt) ExecLast(params ...interface{}) (row mysql.Row, res mysql.Result, err error) {

	if err = s.con.connectIfNotConnected(); err != nil {
		return
	}
	nn := 0
	for {
		if row, res, err = s.Raw.ExecLast(params...); err == nil {
			return
		}

		if s.needsRepreparing(err) {
			if s.con.reprepare(s) != nil {
				return
			}

			// Try again
			continue
		}

		if s.con.reconnectIfNetErr(&nn, &err); err != nil {
			return
		}
	}
	panic(nil)
}
