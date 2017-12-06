package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/empty"
	gw "github.com/grpc-ecosystem/grpc-gateway/examples/examplepb"
	sub "github.com/grpc-ecosystem/grpc-gateway/examples/sub"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
)

type errorBody struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

func TestEcho(t *testing.T) {
	if testing.Short() {
		t.Skip()
		return
	}

	testEcho(t, 8080, "application/json")
	testEchoBody(t, 8080)
}

func TestForwardResponseOption(t *testing.T) {
	go func() {
		if err := Run(
			":8081",
			runtime.WithForwardResponseOption(
				func(_ context.Context, w http.ResponseWriter, _ proto.Message) error {
					w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1.1+json")
					return nil
				},
			),
		); err != nil {
			t.Errorf("gw.Run() failed with %v; want success", err)
			return
		}
	}()

	time.Sleep(100 * time.Millisecond)
	testEcho(t, 8081, "application/vnd.docker.plugins.v1.1+json")
}

func testEcho(t *testing.T, port int, contentType string) {
	url := fmt.Sprintf("http://localhost:%d/v1/example/echo/myid", port)
	resp, err := http.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Errorf("http.Post(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("iotuil.ReadAll(resp.Body) failed with %v; want success", err)
		return
	}

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
		t.Logf("%s", buf)
	}

	var msg gw.SimpleMessage
	if err := jsonpb.UnmarshalString(string(buf), &msg); err != nil {
		t.Errorf("jsonpb.UnmarshalString(%s, &msg) failed with %v; want success", buf, err)
		return
	}
	if got, want := msg.Id, "myid"; got != want {
		t.Errorf("msg.Id = %q; want %q", got, want)
	}

	if value := resp.Header.Get("Content-Type"); value != contentType {
		t.Errorf("Content-Type was %s, wanted %s", value, contentType)
	}
}

func testEchoBody(t *testing.T, port int) {
	sent := gw.SimpleMessage{Id: "example"}
	var m jsonpb.Marshaler
	payload, err := m.MarshalToString(&sent)
	if err != nil {
		t.Fatalf("m.MarshalToString(%#v) failed with %v; want success", payload, err)
	}

	url := fmt.Sprintf("http://localhost:%d/v1/example/echo_body", port)
	resp, err := http.Post(url, "", strings.NewReader(payload))
	if err != nil {
		t.Errorf("http.Post(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("iotuil.ReadAll(resp.Body) failed with %v; want success", err)
		return
	}

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
		t.Logf("%s", buf)
	}

	var received gw.SimpleMessage
	if err := jsonpb.UnmarshalString(string(buf), &received); err != nil {
		t.Errorf("jsonpb.UnmarshalString(%s, &msg) failed with %v; want success", buf, err)
		return
	}
	if got, want := received, sent; !reflect.DeepEqual(got, want) {
		t.Errorf("msg.Id = %q; want %q", got, want)
	}

	if got, want := resp.Header.Get("Grpc-Metadata-Foo"), "foo1"; got != want {
		t.Errorf("Grpc-Metadata-Foo was %q, wanted %q", got, want)
	}
	if got, want := resp.Header.Get("Grpc-Metadata-Bar"), "bar1"; got != want {
		t.Errorf("Grpc-Metadata-Bar was %q, wanted %q", got, want)
	}

	if got, want := resp.Trailer.Get("Grpc-Trailer-Foo"), "foo2"; got != want {
		t.Errorf("Grpc-Trailer-Foo was %q, wanted %q", got, want)
	}
	if got, want := resp.Trailer.Get("Grpc-Trailer-Bar"), "bar2"; got != want {
		t.Errorf("Grpc-Trailer-Bar was %q, wanted %q", got, want)
	}
}

func TestABE(t *testing.T) {
	if testing.Short() {
		t.Skip()
		return
	}

	testABECreate(t, 8080)
	testABECreateBody(t, 8080)
	testABEBulkCreate(t, 8080)
	testABELookup(t, 8080)
	testABELookupNotFound(t, 8080)
	testABEList(t, 8080)
	testABEBulkEcho(t, 8080)
	testABEBulkEchoZeroLength(t, 8080)
	testAdditionalBindings(t, 8080)
}

func testABECreate(t *testing.T, port int) {
	want := gw.ABitOfEverything{
		FloatValue:               1.5,
		DoubleValue:              2.5,
		Int64Value:               4294967296,
		Uint64Value:              9223372036854775807,
		Int32Value:               -2147483648,
		Fixed64Value:             9223372036854775807,
		Fixed32Value:             4294967295,
		BoolValue:                true,
		StringValue:              "strprefix/foo",
		Uint32Value:              4294967295,
		Sfixed32Value:            2147483647,
		Sfixed64Value:            -4611686018427387904,
		Sint32Value:              2147483647,
		Sint64Value:              4611686018427387903,
		NonConventionalNameValue: "camelCase",
	}
	url := fmt.Sprintf("http://localhost:%d/v1/example/a_bit_of_everything/%f/%f/%d/separator/%d/%d/%d/%d/%v/%s/%d/%d/%d/%d/%d/%s", port, want.FloatValue, want.DoubleValue, want.Int64Value, want.Uint64Value, want.Int32Value, want.Fixed64Value, want.Fixed32Value, want.BoolValue, want.StringValue, want.Uint32Value, want.Sfixed32Value, want.Sfixed64Value, want.Sint32Value, want.Sint64Value, want.NonConventionalNameValue)

	resp, err := http.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Errorf("http.Post(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("iotuil.ReadAll(resp.Body) failed with %v; want success", err)
		return
	}

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
		t.Logf("%s", buf)
	}

	var msg gw.ABitOfEverything
	if err := jsonpb.UnmarshalString(string(buf), &msg); err != nil {
		t.Errorf("jsonpb.UnmarshalString(%s, &msg) failed with %v; want success", buf, err)
		return
	}
	if msg.Uuid == "" {
		t.Error("msg.Uuid is empty; want not empty")
	}
	msg.Uuid = ""
	if got := msg; !reflect.DeepEqual(got, want) {
		t.Errorf("msg= %v; want %v", &got, &want)
	}
}

func testABECreateBody(t *testing.T, port int) {
	want := gw.ABitOfEverything{
		FloatValue:               1.5,
		DoubleValue:              2.5,
		Int64Value:               4294967296,
		Uint64Value:              9223372036854775807,
		Int32Value:               -2147483648,
		Fixed64Value:             9223372036854775807,
		Fixed32Value:             4294967295,
		BoolValue:                true,
		StringValue:              "strprefix/foo",
		Uint32Value:              4294967295,
		Sfixed32Value:            2147483647,
		Sfixed64Value:            -4611686018427387904,
		Sint32Value:              2147483647,
		Sint64Value:              4611686018427387903,
		NonConventionalNameValue: "camelCase",

		Nested: []*gw.ABitOfEverything_Nested{
			{
				Name:   "bar",
				Amount: 10,
			},
			{
				Name:   "baz",
				Amount: 20,
			},
		},
		RepeatedStringValue: []string{"a", "b", "c"},
		OneofValue: &gw.ABitOfEverything_OneofString{
			OneofString: "x",
		},
		MapValue: map[string]gw.NumericEnum{
			"a": gw.NumericEnum_ONE,
			"b": gw.NumericEnum_ZERO,
		},
		MappedStringValue: map[string]string{
			"a": "x",
			"b": "y",
		},
		MappedNestedValue: map[string]*gw.ABitOfEverything_Nested{
			"a": {Name: "x", Amount: 1},
			"b": {Name: "y", Amount: 2},
		},
	}
	url := fmt.Sprintf("http://localhost:%d/v1/example/a_bit_of_everything", port)
	var m jsonpb.Marshaler
	payload, err := m.MarshalToString(&want)
	if err != nil {
		t.Fatalf("m.MarshalToString(%#v) failed with %v; want success", want, err)
	}

	resp, err := http.Post(url, "application/json", strings.NewReader(payload))
	if err != nil {
		t.Errorf("http.Post(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("iotuil.ReadAll(resp.Body) failed with %v; want success", err)
		return
	}

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
		t.Logf("%s", buf)
	}

	var msg gw.ABitOfEverything
	if err := jsonpb.UnmarshalString(string(buf), &msg); err != nil {
		t.Errorf("jsonpb.UnmarshalString(%s, &msg) failed with %v; want success", buf, err)
		return
	}
	if msg.Uuid == "" {
		t.Error("msg.Uuid is empty; want not empty")
	}
	msg.Uuid = ""
	if got := msg; !reflect.DeepEqual(got, want) {
		t.Errorf("msg= %v; want %v", &got, &want)
	}
}

func testABEBulkCreate(t *testing.T, port int) {
	count := 0
	r, w := io.Pipe()
	go func(w io.WriteCloser) {
		defer func() {
			if cerr := w.Close(); cerr != nil {
				t.Errorf("w.Close() failed with %v; want success", cerr)
			}
		}()
		for _, val := range []string{
			"foo", "bar", "baz", "qux", "quux",
		} {
			want := gw.ABitOfEverything{
				FloatValue:               1.5,
				DoubleValue:              2.5,
				Int64Value:               4294967296,
				Uint64Value:              9223372036854775807,
				Int32Value:               -2147483648,
				Fixed64Value:             9223372036854775807,
				Fixed32Value:             4294967295,
				BoolValue:                true,
				StringValue:              fmt.Sprintf("strprefix/%s", val),
				Uint32Value:              4294967295,
				Sfixed32Value:            2147483647,
				Sfixed64Value:            -4611686018427387904,
				Sint32Value:              2147483647,
				Sint64Value:              4611686018427387903,
				NonConventionalNameValue: "camelCase",

				Nested: []*gw.ABitOfEverything_Nested{
					{
						Name:   "hoge",
						Amount: 10,
					},
					{
						Name:   "fuga",
						Amount: 20,
					},
				},
			}
			var m jsonpb.Marshaler
			if err := m.Marshal(w, &want); err != nil {
				t.Fatalf("m.Marshal(%#v, w) failed with %v; want success", want, err)
			}
			if _, err := io.WriteString(w, "\n"); err != nil {
				t.Errorf("w.Write(%q) failed with %v; want success", "\n", err)
				return
			}
			count++
		}
	}(w)
	url := fmt.Sprintf("http://localhost:%d/v1/example/a_bit_of_everything/bulk", port)
	resp, err := http.Post(url, "application/json", r)
	if err != nil {
		t.Errorf("http.Post(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("iotuil.ReadAll(resp.Body) failed with %v; want success", err)
		return
	}

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
		t.Logf("%s", buf)
	}

	var msg empty.Empty
	if err := jsonpb.UnmarshalString(string(buf), &msg); err != nil {
		t.Errorf("jsonpb.UnmarshalString(%s, &msg) failed with %v; want success", buf, err)
		return
	}

	if got, want := resp.Header.Get("Grpc-Metadata-Count"), fmt.Sprintf("%d", count); got != want {
		t.Errorf("Grpc-Metadata-Count was %q, wanted %q", got, want)
	}

	if got, want := resp.Trailer.Get("Grpc-Trailer-Foo"), "foo2"; got != want {
		t.Errorf("Grpc-Trailer-Foo was %q, wanted %q", got, want)
	}
	if got, want := resp.Trailer.Get("Grpc-Trailer-Bar"), "bar2"; got != want {
		t.Errorf("Grpc-Trailer-Bar was %q, wanted %q", got, want)
	}
}

func testABELookup(t *testing.T, port int) {
	url := fmt.Sprintf("http://localhost:%d/v1/example/a_bit_of_everything", port)
	cresp, err := http.Post(url, "application/json", strings.NewReader(`
		{"bool_value": true, "string_value": "strprefix/example"}
	`))
	if err != nil {
		t.Errorf("http.Post(%q) failed with %v; want success", url, err)
		return
	}
	defer cresp.Body.Close()
	buf, err := ioutil.ReadAll(cresp.Body)
	if err != nil {
		t.Errorf("iotuil.ReadAll(cresp.Body) failed with %v; want success", err)
		return
	}
	if got, want := cresp.StatusCode, http.StatusOK; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
		t.Logf("%s", buf)
		return
	}

	var want gw.ABitOfEverything
	if err := jsonpb.UnmarshalString(string(buf), &want); err != nil {
		t.Errorf("jsonpb.UnmarshalString(%s, &want) failed with %v; want success", buf, err)
		return
	}

	url = fmt.Sprintf("%s/%s", url, want.Uuid)
	resp, err := http.Get(url)
	if err != nil {
		t.Errorf("http.Get(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()

	buf, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("ioutil.ReadAll(resp.Body) failed with %v; want success", err)
		return
	}

	var msg gw.ABitOfEverything
	if err := jsonpb.UnmarshalString(string(buf), &msg); err != nil {
		t.Errorf("jsonpb.UnmarshalString(%s, &msg) failed with %v; want success", buf, err)
		return
	}
	if got := msg; !reflect.DeepEqual(got, want) {
		t.Errorf("msg= %v; want %v", &got, &want)
	}

	if got, want := resp.Header.Get("Grpc-Metadata-Uuid"), want.Uuid; got != want {
		t.Errorf("Grpc-Metadata-Uuid was %s, wanted %s", got, want)
	}
}

func testABELookupNotFound(t *testing.T, port int) {
	url := fmt.Sprintf("http://localhost:%d/v1/example/a_bit_of_everything", port)
	uuid := "not_exist"
	url = fmt.Sprintf("%s/%s", url, uuid)
	resp, err := http.Get(url)
	if err != nil {
		t.Errorf("http.Get(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("ioutil.ReadAll(resp.Body) failed with %v; want success", err)
		return
	}

	if got, want := resp.StatusCode, http.StatusNotFound; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
		t.Logf("%s", buf)
		return
	}

	var msg errorBody
	if err := json.Unmarshal(buf, &msg); err != nil {
		t.Errorf("jsonpb.UnmarshalString(%s, &msg) failed with %v; want success", buf, err)
		return
	}

	if got, want := msg.Code, int(codes.NotFound); got != want {
		t.Errorf("msg.Code = %d; want %d", got, want)
		return
	}

	if got, want := msg.Error, "not found"; got != want {
		t.Errorf("msg.Error = %s; want %s", got, want)
		return
	}

	if got, want := resp.Header.Get("Grpc-Metadata-Uuid"), uuid; got != want {
		t.Errorf("Grpc-Metadata-Uuid was %s, wanted %s", got, want)
	}
	if got, want := resp.Trailer.Get("Grpc-Trailer-Foo"), "foo2"; got != want {
		t.Errorf("Grpc-Trailer-Foo was %q, wanted %q", got, want)
	}
	if got, want := resp.Trailer.Get("Grpc-Trailer-Bar"), "bar2"; got != want {
		t.Errorf("Grpc-Trailer-Bar was %q, wanted %q", got, want)
	}
}

func testABEList(t *testing.T, port int) {
	url := fmt.Sprintf("http://localhost:%d/v1/example/a_bit_of_everything", port)
	resp, err := http.Get(url)
	if err != nil {
		t.Errorf("http.Get(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	var i int
	for i = 0; ; i++ {
		var item struct {
			Result json.RawMessage        `json:"result"`
			Error  map[string]interface{} `json:"error"`
		}
		err := dec.Decode(&item)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("dec.Decode(&item) failed with %v; want success; i = %d", err, i)
		}
		if len(item.Error) != 0 {
			t.Errorf("item.Error = %#v; want empty; i = %d", item.Error, i)
			continue
		}
		var msg gw.ABitOfEverything
		if err := jsonpb.UnmarshalString(string(item.Result), &msg); err != nil {
			t.Errorf("jsonpb.UnmarshalString(%s, &msg) failed with %v; want success", item.Result, err)
		}
	}
	if i <= 0 {
		t.Errorf("i == %d; want > 0", i)
	}

	value := resp.Header.Get("Grpc-Metadata-Count")
	if value == "" {
		t.Errorf("Grpc-Metadata-Count should not be empty")
	}

	count, err := strconv.Atoi(value)
	if err != nil {
		t.Errorf("failed to Atoi %q: %v", value, err)
	}

	if count <= 0 {
		t.Errorf("count == %d; want > 0", count)
	}
}

func testABEBulkEcho(t *testing.T, port int) {
	reqr, reqw := io.Pipe()
	var wg sync.WaitGroup
	var want []*sub.StringMessage
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer reqw.Close()
		var m jsonpb.Marshaler
		for i := 0; i < 1000; i++ {
			msg := sub.StringMessage{Value: proto.String(fmt.Sprintf("message %d", i))}
			buf, err := m.MarshalToString(&msg)
			if err != nil {
				t.Errorf("m.Marshal(%v) failed with %v; want success", &msg, err)
				return
			}
			if _, err := fmt.Fprintln(reqw, buf); err != nil {
				t.Errorf("fmt.Fprintln(reqw, %q) failed with %v; want success", buf, err)
				return
			}
			want = append(want, &msg)
		}
	}()

	url := fmt.Sprintf("http://localhost:%d/v1/example/a_bit_of_everything/echo", port)
	req, err := http.NewRequest("POST", url, reqr)
	if err != nil {
		t.Errorf("http.NewRequest(%q, %q, reqr) failed with %v; want success", "POST", url, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Transfer-Encoding", "chunked")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("http.Post(%q, %q, req) failed with %v; want success", url, "application/json", err)
		return
	}
	defer resp.Body.Close()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
	}

	var got []*sub.StringMessage
	wg.Add(1)
	go func() {
		defer wg.Done()

		dec := json.NewDecoder(resp.Body)
		for i := 0; ; i++ {
			var item struct {
				Result json.RawMessage        `json:"result"`
				Error  map[string]interface{} `json:"error"`
			}
			err := dec.Decode(&item)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("dec.Decode(&item) failed with %v; want success; i = %d", err, i)
			}
			if len(item.Error) != 0 {
				t.Errorf("item.Error = %#v; want empty; i = %d", item.Error, i)
				continue
			}
			var msg sub.StringMessage
			if err := jsonpb.UnmarshalString(string(item.Result), &msg); err != nil {
				t.Errorf("jsonpb.UnmarshalString(%q, &msg) failed with %v; want success", item.Result, err)
			}
			got = append(got, &msg)
		}
	}()

	wg.Wait()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got = %v; want %v", got, want)
	}
}

func testABEBulkEchoZeroLength(t *testing.T, port int) {
	url := fmt.Sprintf("http://localhost:%d/v1/example/a_bit_of_everything/echo", port)
	req, err := http.NewRequest("POST", url, bytes.NewReader(nil))
	if err != nil {
		t.Errorf("http.NewRequest(%q, %q, bytes.NewReader(nil)) failed with %v; want success", "POST", url, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Transfer-Encoding", "chunked")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("http.Post(%q, %q, req) failed with %v; want success", url, "application/json", err)
		return
	}
	defer resp.Body.Close()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
	}

	dec := json.NewDecoder(resp.Body)
	var item struct {
		Result json.RawMessage        `json:"result"`
		Error  map[string]interface{} `json:"error"`
	}
	if err := dec.Decode(&item); err == nil {
		t.Errorf("dec.Decode(&item) succeeded; want io.EOF; item = %#v", item)
	} else if err != io.EOF {
		t.Errorf("dec.Decode(&item) failed with %v; want success", err)
		return
	}
}

func testAdditionalBindings(t *testing.T, port int) {
	for i, f := range []func() *http.Response{
		func() *http.Response {
			url := fmt.Sprintf("http://localhost:%d/v1/example/a_bit_of_everything/echo/hello", port)
			resp, err := http.Get(url)
			if err != nil {
				t.Errorf("http.Get(%q) failed with %v; want success", url, err)
				return nil
			}
			return resp
		},
		func() *http.Response {
			url := fmt.Sprintf("http://localhost:%d/v2/example/echo", port)
			resp, err := http.Post(url, "application/json", strings.NewReader(`"hello"`))
			if err != nil {
				t.Errorf("http.Post(%q, %q, %q) failed with %v; want success", url, "application/json", `"hello"`, err)
				return nil
			}
			return resp
		},
		func() *http.Response {
			url := fmt.Sprintf("http://localhost:%d/v2/example/echo?value=hello", port)
			resp, err := http.Get(url)
			if err != nil {
				t.Errorf("http.Get(%q) failed with %v; want success", url, err)
				return nil
			}
			return resp
		},
	} {
		resp := f()
		if resp == nil {
			continue
		}

		defer resp.Body.Close()
		buf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("iotuil.ReadAll(resp.Body) failed with %v; want success; i=%d", err, i)
			return
		}
		if got, want := resp.StatusCode, http.StatusOK; got != want {
			t.Errorf("resp.StatusCode = %d; want %d; i=%d", got, want, i)
			t.Logf("%s", buf)
		}

		var msg sub.StringMessage
		if err := jsonpb.UnmarshalString(string(buf), &msg); err != nil {
			t.Errorf("jsonpb.UnmarshalString(%s, &msg) failed with %v; want success; %d", buf, err, i)
			return
		}
		if got, want := msg.GetValue(), "hello"; got != want {
			t.Errorf("msg.GetValue() = %q; want %q", got, want)
		}
	}
}

func TestTimeout(t *testing.T) {
	url := "http://localhost:8080/v2/example/timeout"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Errorf(`http.NewRequest("GET", %q, nil) failed with %v; want success`, url, err)
		return
	}
	req.Header.Set("Grpc-Timeout", "10m")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("http.DefaultClient.Do(%#v) failed with %v; want success", req, err)
		return
	}
	defer resp.Body.Close()

	if got, want := resp.StatusCode, http.StatusRequestTimeout; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
	}
}

func TestUnknownPath(t *testing.T) {
	url := "http://localhost:8080"
	resp, err := http.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Errorf("http.Post(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("iotuil.ReadAll(resp.Body) failed with %v; want success", err)
		return
	}

	if got, want := resp.StatusCode, http.StatusNotFound; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
		t.Logf("%s", buf)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	url := "http://localhost:8080/v1/example/echo/myid"
	resp, err := http.Get(url)
	if err != nil {
		t.Errorf("http.Post(%q) failed with %v; want success", url, err)
		return
	}
	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("iotuil.ReadAll(resp.Body) failed with %v; want success", err)
		return
	}

	if got, want := resp.StatusCode, http.StatusMethodNotAllowed; got != want {
		t.Errorf("resp.StatusCode = %d; want %d", got, want)
		t.Logf("%s", buf)
	}
}
