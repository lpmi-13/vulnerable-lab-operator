package notifier

import (
	"testing"
	"time"
)

const testMessageVulnApplied = "vulnerability-applied"

// receiveWithTimeout attempts to receive from a channel with a timeout
//
//nolint:unparam // duration parameter kept for flexibility even though currently always the same
func receiveWithTimeout(ch <-chan string, d time.Duration) (string, bool) {
	select {
	case msg := <-ch:
		return msg, true
	case <-time.After(d):
		return "", false
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

	// Verify subscriber was registered
	n.mu.RLock()
	count := len(n.subscribers)
	n.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 subscriber, got %d", count)
	}

	// Call cleanup
	cleanup()

	// Verify cleanup closes channel
	_, ok := <-ch
	if ok {
		t.Error("channel was not closed by cleanup")
	}

	// Verify subscriber was removed
	n.mu.RLock()
	count = len(n.subscribers)
	n.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 subscribers after cleanup, got %d", count)
	}
}

func TestSendImmediateDelivery(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	// Clear any initial state messages
	select {
	case <-ch:
	default:
	}

	// First message should be delivered immediately
	n.Send("lab1", testMessageVulnApplied)

	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected message to be delivered immediately")
	}
	if msg != testMessageVulnApplied {
		t.Errorf("expected %q, got %q", testMessageVulnApplied, msg)
	}
}

func TestSendDuplicateSuppression(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	// Clear any initial state messages
	select {
	case <-ch:
	default:
	}

	// Send first message
	n.Send("lab1", testMessageVulnApplied)
	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected first message")
	}
	if msg != testMessageVulnApplied {
		t.Errorf("expected %q, got %q", testMessageVulnApplied, msg)
	}

	// Send same message again immediately - should be suppressed
	n.Send("lab1", testMessageVulnApplied)

	// Should not receive duplicate
	_, ok = receiveWithTimeout(ch, 100*time.Millisecond)
	if ok {
		t.Error("duplicate message should have been suppressed")
	}
}

func TestSendDebouncing(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	// Clear any initial state messages
	select {
	case <-ch:
	default:
	}

	// Send first message
	n.Send("lab1", testMessageVulnApplied)
	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected first message")
	}
	if msg != testMessageVulnApplied {
		t.Errorf("expected %q, got %q", testMessageVulnApplied, msg)
	}

	// Send second message within 2 seconds (should be debounced)
	time.Sleep(500 * time.Millisecond)
	n.Send("lab1", "vulnerability-remediated")

	// Should not receive immediately
	_, ok = receiveWithTimeout(ch, 100*time.Millisecond)
	if ok {
		t.Error("message should have been debounced, not delivered immediately")
	}

	// Wait for debounce interval to complete (2 seconds from first message)
	time.Sleep(2 * time.Second)

	// Should now receive the debounced message
	msg, ok = receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected debounced message after interval")
	}
	if msg != "vulnerability-remediated" {
		t.Errorf("expected 'vulnerability-remediated', got %q", msg)
	}
}

func TestSendNilNotifierNoOp(t *testing.T) {
	var n *Notifier
	// Should not panic
	n.Send("lab1", "test")
}

func TestSendChangeImmediateFirstCall(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	// Clear any initial state messages
	select {
	case <-ch:
	default:
	}

	// First SendChange should deliver immediately
	n.SendChange("lab1", "change-detected")

	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected first SendChange to deliver immediately")
	}
	if msg != "change-detected" {
		t.Errorf("expected 'change-detected', got %q", msg)
	}
}

func TestSendChangeCooldown(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	// Clear any initial state messages
	select {
	case <-ch:
	default:
	}

	// First SendChange
	n.SendChange("lab1", "change-detected-1")
	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("expected first message")
	}
	if msg != "change-detected-1" {
		t.Errorf("expected 'change-detected-1', got %q", msg)
	}

	// Second SendChange within cooldown window (30s) should be suppressed
	time.Sleep(100 * time.Millisecond)
	n.SendChange("lab1", "change-detected-2")

	// Should not receive second message
	_, ok = receiveWithTimeout(ch, 100*time.Millisecond)
	if ok {
		t.Error("second SendChange within cooldown should have been suppressed")
	}
}

func TestSendChangeNilNotifierNoOp(t *testing.T) {
	var n *Notifier
	// Should not panic
	n.SendChange("lab1", "test")
}

func TestFanOutToMultipleSubscribers(t *testing.T) {
	n := New()

	// Subscribe 3 clients
	ch1, cleanup1 := n.Subscribe()
	defer cleanup1()
	ch2, cleanup2 := n.Subscribe()
	defer cleanup2()
	ch3, cleanup3 := n.Subscribe()
	defer cleanup3()

	// Clear any initial state messages
	for _, ch := range []<-chan string{ch1, ch2, ch3} {
		select {
		case <-ch:
		default:
		}
	}

	// Send a message
	n.Send("lab1", "test-message")

	// All subscribers should receive it
	for i, ch := range []<-chan string{ch1, ch2, ch3} {
		msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
		if !ok {
			t.Errorf("subscriber %d did not receive message", i+1)
			continue
		}
		if msg != "test-message" {
			t.Errorf("subscriber %d got %q, want 'test-message'", i+1, msg)
		}
	}
}

func TestFanOutSkipsFullChannels(t *testing.T) {
	n := New()
	ch, cleanup := n.Subscribe()
	defer cleanup()

	// Clear any initial state messages
	select {
	case <-ch:
	default:
	}

	// Fill the channel buffer (capacity is 10)
	for i := 0; i < 10; i++ {
		n.Send("lab1", "msg")
		time.Sleep(10 * time.Millisecond) // Small delay to ensure messages are sent
	}

	// Channel should now be full
	// Sending another message should not block (it should skip the full channel)
	done := make(chan bool)
	go func() {
		n.Send("lab2", "should-skip")
		done <- true
	}()

	// If it blocks, this will timeout
	select {
	case <-done:
		// Good, it didn't block
	case <-time.After(500 * time.Millisecond):
		t.Error("Send blocked on full channel instead of skipping")
	}
}

func TestSubscribeCleanup(t *testing.T) {
	n := New()

	// Create 2 subscribers
	ch1, cleanup1 := n.Subscribe()
	defer cleanup1()
	ch2, cleanup2 := n.Subscribe()

	// Clear any initial state messages
	for _, ch := range []<-chan string{ch1, ch2} {
		select {
		case <-ch:
		default:
		}
	}

	// Clean up second subscriber
	cleanup2()

	// Send a message
	n.Send("lab1", "test-message")

	// First subscriber should receive it
	msg, ok := receiveWithTimeout(ch1, 100*time.Millisecond)
	if !ok {
		t.Error("subscriber 1 should have received message")
	}
	if msg != "test-message" {
		t.Errorf("got %q, want 'test-message'", msg)
	}

	// Second subscriber's channel should be closed
	_, ok = <-ch2
	if ok {
		t.Error("subscriber 2 channel should be closed")
	}
}

func TestSubscribeReceivesCurrentState(t *testing.T) {
	n := New()

	// Send a message before subscribing
	n.Send("lab1", "initial-state")
	time.Sleep(100 * time.Millisecond) // Let the send complete

	// New subscriber should receive current state
	ch, cleanup := n.Subscribe()
	defer cleanup()

	msg, ok := receiveWithTimeout(ch, 100*time.Millisecond)
	if !ok {
		t.Fatal("new subscriber should receive current state immediately")
	}
	if msg != "initial-state" {
		t.Errorf("expected 'initial-state', got %q", msg)
	}
}
