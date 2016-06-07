// This file is there temporary and it isn't any example of how to use mymysql.
package main

import (
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ziutek/mymysql/mysql"
	_ "github.com/ziutek/mymysql/native"
)

const (
	n_sends      = 3 * 1000
	n_goroutines = 100
)

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	work_chan := make(chan bool)
	sends_chan := make(chan bool)
	results_chan := make(chan bool, n_sends)

	signal_chan := make(chan os.Signal, 1)
	signal.Notify(signal_chan, syscall.SIGINT)

	for i := 0; i < n_goroutines; i++ {
		go func() {
			conn := mysql.New(
				"tcp", "", "127.0.0.1:3306",
				"testuser", "TestPasswd9",
			)
			conn.SetTimeout(2 * time.Second)
			defer conn.Close()

			for {
				<-work_chan

				if !conn.IsConnected() {
					checkErr(conn.Reconnect())
				}

				res, err := conn.Start("show processlist")
				checkErr(err)
				row := res.MakeRow()
				for {
					err := res.ScanRow(row)
					if err == io.EOF {
						break
					}
					checkErr(err)
					// _, _ = row.ForceUint64(0), row.ForceUint(1)
				}

				// sleep_time := time.Duration(rand.Intn(10)) * time.Millisecond
				// time.Sleep(sleep_time)

				results_chan <- true
			}
		}()
	}

	go func() {
		for i := 0; i < n_sends; i++ {
			work_chan <- true
			sends_chan <- true
		}
	}()

	done_sends := 0
	ticker := time.NewTicker(1 * time.Second)

	for got_results := 0; got_results < n_sends; {
		select {
		case <-results_chan:
			got_results++
		case <-sends_chan:
			done_sends++
		case <-ticker.C:
			log.Printf("done %d sends, got %d results", done_sends, got_results)
		case <-signal_chan:
			panic("show me the goroutines")
		}
	}
	log.Printf("got all %d results", n_sends)

	// panic("show me the goroutines")
}
