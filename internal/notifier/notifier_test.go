package notifier

import (
	"fmt"
	"testing"
	"time"
)

const testMessageVulnApplied = "vulnerability-applied"

// receiveWithTimeout attempts to receive from a channel with a timeout.
//
//nolint:unparam // duration parameter kept for flexibility even though currently always the same
func receiveWithTimeout(ch <-chan Event, d time.Duration) (Event, bool) {
	select {
	case msg := <-ch:
		return msg, true
	case <-time.After(d):
		return Event{}, false
	}
}

func TestNew(t *testing.T) {
	n := New()
	if n == nil {
		t.Fatal("New() returned nil")
	}
	if n.subscribers == nil {
		t.Error("subscribers map not initialized")
	}
	if n.lastNotified == nil {
		t.Error("lastNotified map not initialized")
	}
	if n.lastChangeNotified == nil {
		t.Error("lastChangeNotified map not initialized")
	}
	if n.pendingTimers == nil {
		t.Error("pendingTimers map not initialized")
	}
}

func TestSubscribe(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()

	if ch == nil {
		t.Fatal("Subscribe() returned nil channel")
	}
	if cleanup == nil {
		t.Fatal("Subscribe() returned nil cleanup function")
	}

	// Verify subscriber was registered.
	n.mu.RLock()
	count := len(n.subscribers)
	n.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 subscriber, got %d", count)
	}

	// Call cleanup.
	cleanup()

	// Verify cleanup closes channel.
	_, ok := <-ch
	if ok {
		t.Error("channel was not closed by cleanup")
	}

	// Verify subscriber was removed.
	n.mu.RLock()
	count = len(n.subscribers)
	n.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 subscribers after cleanup, got %d", count)
	}
}

func TestSendEventImmediateDelivery(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	n.SendEvent("lab1", Event{Message: testMessageVulnApplied, ChallengeID: "c1"})

	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected message to be delivered immediately")
	}
	if msg.Message != testMessageVulnApplied {
		t.Errorf("expected %q, got %q", testMessageVulnApplied, msg.Message)
	}
	if msg.ChallengeID != "c1" {
		t.Errorf("expected challenge ID c1, got %q", msg.ChallengeID)
	}
}

func TestSendEventDuplicateSuppression(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	event := Event{Message: testMessageVulnApplied, ChallengeID: "c1"}
	n.SendEvent("lab1", event)

	_, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected first message")
	}

	// Same message + challenge should be suppressed.
	n.SendEvent("lab1", event)
	_, ok = receiveWithTimeout(ch, 100*time.Millisecond)
	if ok {
		t.Error("duplicate event should have been suppressed")
	}
}

func TestSendEventNotSuppressedAcrossChallenges(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	n.SendEvent("lab1", Event{Message: testMessageVulnApplied, ChallengeID: "c1"})
	_, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected first event")
	}

	// Avoid the debounce interval so this test exercises dedupe behavior only.
	time.Sleep(2100 * time.Millisecond)

	// Same message with a different challenge ID should be treated as new.
	n.SendEvent("lab1", Event{Message: testMessageVulnApplied, ChallengeID: "c2"})
	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected second event for new challenge")
	}
	if msg.ChallengeID != "c2" {
		t.Errorf("expected challenge ID c2, got %q", msg.ChallengeID)
	}
}

func TestSendEventDebouncing(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	n.SendEvent("lab1", Event{Message: testMessageVulnApplied, ChallengeID: "c1"})
	_, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected first event")
	}

	// Second event within 2 seconds should be debounced.
	time.Sleep(500 * time.Millisecond)
	n.SendEvent("lab1", Event{Message: "vulnerability-remediated", ChallengeID: "c1"})

	_, ok = receiveWithTimeout(ch, 100*time.Millisecond)
	if ok {
		t.Error("event should have been debounced, not delivered immediately")
	}

	time.Sleep(2 * time.Second)

	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected debounced event after interval")
	}
	if msg.Message != "vulnerability-remediated" {
		t.Errorf("expected %q, got %q", "vulnerability-remediated", msg.Message)
	}
}

func TestSendEventNilNotifierNoOp(t *testing.T) {
	var n *Notifier
	n.SendEvent("lab1", Event{Message: "test"})
}

func TestSendChangeEventImmediateFirstCall(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	n.SendChangeEvent("lab1", Event{Message: "change-detected", ChallengeID: "c1"})

	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected first SendChangeEvent to deliver immediately")
	}
	if msg.Message != "change-detected" {
		t.Errorf("expected %q, got %q", "change-detected", msg.Message)
	}
}

func TestSendChangeEventCooldown(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	n.SendChangeEvent("lab1", Event{Message: "change-detected-1", ChallengeID: "c1"})
	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected first message")
	}
	if msg.Message != "change-detected-1" {
		t.Errorf("expected %q, got %q", "change-detected-1", msg.Message)
	}

	time.Sleep(100 * time.Millisecond)
	n.SendChangeEvent("lab1", Event{Message: "change-detected-2", ChallengeID: "c1"})

	_, ok = receiveWithTimeout(ch, 100*time.Millisecond)
	if ok {
		t.Error("second SendChangeEvent within cooldown should have been suppressed")
	}
}

func TestSendChangeEventNilNotifierNoOp(t *testing.T) {
	var n *Notifier
	n.SendChangeEvent("lab1", Event{Message: "test"})
}

func TestFanOutToMultipleSubscribers(t *testing.T) {
	n := New()

	ch1, cleanup1 := n.Subscribe()
	defer cleanup1()
	ch2, cleanup2 := n.Subscribe()
	defer cleanup2()
	ch3, cleanup3 := n.Subscribe()
	defer cleanup3()

	n.SendEvent("lab1", Event{Message: "test-message", ChallengeID: "c1"})

	for i, ch := range []<-chan Event{ch1, ch2, ch3} {
		msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
		if !ok {
			t.Errorf("subscriber %d did not receive message", i+1)
			continue
		}
		if msg.Message != "test-message" {
			t.Errorf("subscriber %d got %q, want %q", i+1, msg.Message, "test-message")
		}
	}
}

func TestFanOutSkipsFullChannels(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	// Fill the channel buffer (capacity is 10) using unique labs to bypass per-lab debounce.
	for i := 0; i < 10; i++ {
		n.SendEvent(fmt.Sprintf("lab-%d", i), Event{
			Message:     fmt.Sprintf("msg-%d", i),
			ChallengeID: "c1",
		})
	}

	done := make(chan bool)
	go func() {
		n.SendEvent("lab-overflow", Event{Message: "should-skip", ChallengeID: "c1"})
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("SendEvent blocked on full channel instead of skipping")
	}

	// Drain to keep cleanup predictable.
	for range 10 {
		<-ch
	}
}

func TestSubscribeCleanup(t *testing.T) {
	n := New()

	ch1, cleanup1 := n.Subscribe()
	defer cleanup1()
	ch2, cleanup2 := n.Subscribe()

	cleanup2()

	n.SendEvent("lab1", Event{Message: "test-message", ChallengeID: "c1"})

	msg, ok := receiveWithTimeout(ch1, 100*time.Millisecond)
	if !ok {
		t.Error("subscriber 1 should have received message")
	}
	if msg.Message != "test-message" {
		t.Errorf("got %q, want %q", msg.Message, "test-message")
	}

	_, ok = <-ch2
	if ok {
		t.Error("subscriber 2 channel should be closed")
	}
}

func TestSubscribeReceivesCurrentState(t *testing.T) {
	n := New()

	n.SendEvent("lab1", Event{Message: "initial-state", ChallengeID: "c1"})
	time.Sleep(100 * time.Millisecond)

	ch, cleanup := n.Subscribe()
	defer cleanup()

	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("new subscriber should receive current state immediately")
	}
	if msg.Message != "initial-state" {
		t.Errorf("expected %q, got %q", "initial-state", msg.Message)
	}
}
