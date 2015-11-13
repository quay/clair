package testserver

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"gopkg.in/mgo.v2"
	"gopkg.in/tomb.v2"
)

// TestServer controls a MongoDB server process to be used within test suites.
//
// The test server is started when Session is called the first time and should
// remain running for the duration of all tests, with the Wipe method being
// called between tests (before each of them) to clear stored data. After all tests
// are done, the Stop method should be called to stop the test server.
//
// Before the TestServer is used the SetPath method must be called to define
// the location for the database files to be stored.
type TestServer struct {
	session *mgo.Session
	output  bytes.Buffer
	server  *exec.Cmd
	dbpath  string
	host    string
	tomb    tomb.Tomb
}

// SetPath defines the path to the directory where the database files will be
// stored if it is started. The directory path itself is not created or removed
// by the test helper.
func (ts *TestServer) SetPath(dbpath string) {
	ts.dbpath = dbpath
}

func (ts *TestServer) start() {
	if ts.server != nil {
		panic("TestServer already started")
	}
	if ts.dbpath == "" {
		panic("TestServer.SetPath must be called before using the server")
	}
	mgo.SetStats(true)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("unable to listen on a local address: " + err.Error())
	}
	addr := l.Addr().(*net.TCPAddr)
	l.Close()
	ts.host = addr.String()

	args := []string{
		"--dbpath", ts.dbpath,
		"--bind_ip", "127.0.0.1",
		"--port", strconv.Itoa(addr.Port),
		"--nssize", "1",
		"--noprealloc",
		"--smallfiles",
		"--nojournal",
	}
	ts.tomb = tomb.Tomb{}
	ts.server = exec.Command("mongod", args...)
	ts.server.Stdout = &ts.output
	ts.server.Stderr = &ts.output
	err = ts.server.Start()
	if err != nil {
		panic(err)
	}
	ts.tomb.Go(ts.monitor)
	ts.Wipe()
}

func (ts *TestServer) monitor() error {
	ts.server.Process.Wait()
	if ts.tomb.Alive() {
		// Present some debugging information.
		fmt.Fprintf(os.Stderr, "---- mongod process died unexpectedly:\n")
		fmt.Fprintf(os.Stderr, "%s", ts.output.Bytes())
		fmt.Fprintf(os.Stderr, "---- mongod processes running right now:\n")
		cmd := exec.Command("/bin/sh", "-c", "ps auxw | grep mongod")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		cmd.Run()
		fmt.Fprintf(os.Stderr, "----------------------------------------\n")

		panic("mongod process died unexpectedly")
	}
	return nil
}

// Stop stops the test server process, if it is running.
//
// It's okay to call Stop multiple times. After the test server is
// stopped it cannot be restarted.
//
// All database sessions must be closed before or while the Stop method
// is running. Otherwise Stop will panic after a timeout informing that
// there is a session leak.
func (ts *TestServer) Stop() {
	if ts.session != nil {
		ts.checkSessions()
		if ts.session != nil {
			ts.session.Close()
			ts.session = nil
		}
	}
	if ts.server != nil {
		ts.tomb.Kill(nil)
		ts.server.Process.Kill()
		select {
		case <-ts.tomb.Dead():
		case <-time.After(5 * time.Second):
			panic("timeout waiting for mongod process to die")
		}
		ts.server = nil
	}
}

// Session returns a new session to the server. The returned session
// must be closed after the test is done with it.
//
// The first Session obtained from a TestServer will start it.
func (ts *TestServer) Session() *mgo.Session {
	if ts.server == nil {
		ts.start()
	}
	if ts.session == nil {
		mgo.ResetStats()
		var err error
		ts.session, err = mgo.Dial(ts.host + "/test")
		if err != nil {
			panic(err)
		}
	}
	return ts.session.Copy()
}

// checkSessions ensures all mgo sessions opened were properly closed.
// For slightly faster tests, it may be disabled setting the
// environmnet variable CHECK_SESSIONS to 0.
func (ts *TestServer) checkSessions() {
	if check := os.Getenv("CHECK_SESSIONS"); check == "0" || ts.server == nil || ts.session == nil {
		return
	}
	ts.session.Close()
	ts.session = nil
	for i := 0; i < 100; i++ {
		stats := mgo.GetStats()
		if stats.SocketsInUse == 0 && stats.SocketsAlive == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	panic("There are mgo sessions still alive.")
}

// Wipe drops all created databases and their data.
//
// The MongoDB server remains running if it was prevoiusly running,
// or stopped if it was previously stopped.
//
// All database sessions must be closed before or while the Wipe method
// is running. Otherwise Wipe will panic after a timeout informing that
// there is a session leak.
func (ts *TestServer) Wipe() {
	if ts.server == nil || ts.session == nil {
		return
	}
	ts.checkSessions()
	sessionUnset := ts.session == nil
	session := ts.Session()
	defer session.Close()
	if sessionUnset {
		ts.session.Close()
		ts.session = nil
	}
	names, err := session.DatabaseNames()
	if err != nil {
		panic(err)
	}
	for _, name := range names {
		switch name {
		case "admin", "local", "config":
		default:
			err = session.DB(name).DropDatabase()
			if err != nil {
				panic(err)
			}
		}
	}
}
