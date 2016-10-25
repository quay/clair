package events

import (
	"fmt"
	"testing"
	"time"

	"github.com/docker/engine-api/types/events"
)

func TestEventsLog(t *testing.T) {
	e := New()
	_, l1, _ := e.Subscribe()
	_, l2, _ := e.Subscribe()
	defer e.Evict(l1)
	defer e.Evict(l2)
	count := e.SubscribersCount()
	if count != 2 {
		t.Fatalf("Must be 2 subscribers, got %d", count)
	}
	actor := events.Actor{
		ID:         "cont",
		Attributes: map[string]string{"image": "image"},
	}
	e.Log("test", events.ContainerEventType, actor)
	select {
	case msg := <-l1:
		jmsg, ok := msg.(events.Message)
		if !ok {
			t.Fatalf("Unexpected type %T", msg)
		}
		if len(e.events) != 1 {
			t.Fatalf("Must be only one event, got %d", len(e.events))
		}
		if jmsg.Status != "test" {
			t.Fatalf("Status should be test, got %s", jmsg.Status)
		}
		if jmsg.ID != "cont" {
			t.Fatalf("ID should be cont, got %s", jmsg.ID)
		}
		if jmsg.From != "image" {
			t.Fatalf("From should be image, got %s", jmsg.From)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for broadcasted message")
	}
	select {
	case msg := <-l2:
		jmsg, ok := msg.(events.Message)
		if !ok {
			t.Fatalf("Unexpected type %T", msg)
		}
		if len(e.events) != 1 {
			t.Fatalf("Must be only one event, got %d", len(e.events))
		}
		if jmsg.Status != "test" {
			t.Fatalf("Status should be test, got %s", jmsg.Status)
		}
		if jmsg.ID != "cont" {
			t.Fatalf("ID should be cont, got %s", jmsg.ID)
		}
		if jmsg.From != "image" {
			t.Fatalf("From should be image, got %s", jmsg.From)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for broadcasted message")
	}
}

func TestEventsLogTimeout(t *testing.T) {
	e := New()
	_, l, _ := e.Subscribe()
	defer e.Evict(l)

	c := make(chan struct{})
	go func() {
		actor := events.Actor{
			ID: "image",
		}
		e.Log("test", events.ImageEventType, actor)
		close(c)
	}()

	select {
	case <-c:
	case <-time.After(time.Second):
		t.Fatal("Timeout publishing message")
	}
}

func TestLogEvents(t *testing.T) {
	e := New()

	for i := 0; i < eventsLimit+16; i++ {
		action := fmt.Sprintf("action_%d", i)
		id := fmt.Sprintf("cont_%d", i)
		from := fmt.Sprintf("image_%d", i)

		actor := events.Actor{
			ID:         id,
			Attributes: map[string]string{"image": from},
		}
		e.Log(action, events.ContainerEventType, actor)
	}
	time.Sleep(50 * time.Millisecond)
	current, l, _ := e.Subscribe()
	for i := 0; i < 10; i++ {
		num := i + eventsLimit + 16
		action := fmt.Sprintf("action_%d", num)
		id := fmt.Sprintf("cont_%d", num)
		from := fmt.Sprintf("image_%d", num)

		actor := events.Actor{
			ID:         id,
			Attributes: map[string]string{"image": from},
		}
		e.Log(action, events.ContainerEventType, actor)
	}
	if len(e.events) != eventsLimit {
		t.Fatalf("Must be %d events, got %d", eventsLimit, len(e.events))
	}

	var msgs []events.Message
	for len(msgs) < 10 {
		m := <-l
		jm, ok := (m).(events.Message)
		if !ok {
			t.Fatalf("Unexpected type %T", m)
		}
		msgs = append(msgs, jm)
	}
	if len(current) != eventsLimit {
		t.Fatalf("Must be %d events, got %d", eventsLimit, len(current))
	}
	first := current[0]
	if first.Status != "action_16" {
		t.Fatalf("First action is %s, must be action_16", first.Status)
	}
	last := current[len(current)-1]
	if last.Status != "action_79" {
		t.Fatalf("Last action is %s, must be action_79", last.Status)
	}

	firstC := msgs[0]
	if firstC.Status != "action_80" {
		t.Fatalf("First action is %s, must be action_80", firstC.Status)
	}
	lastC := msgs[len(msgs)-1]
	if lastC.Status != "action_89" {
		t.Fatalf("Last action is %s, must be action_89", lastC.Status)
	}
}
