package notifier

import (
	"sync"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

// Notifier handles sending notifications to SSE clients
type Notifier struct {
	mu                 sync.RWMutex
	subscribers        map[int]chan string
	nextID             int
	lastNotified       map[string]*notificationState
	lastChangeNotified map[string]time.Time
	pendingTimers      map[string]*time.Timer
}

// notificationState tracks the last notification sent for a lab
type notificationState struct {
	lastMessage string
	lastTime    time.Time
	pending     string // Pending message to deliver after debounce interval
}

// New creates a new Notifier instance
func New() *Notifier {
	return &Notifier{
		subscribers:        make(map[int]chan string),
		lastNotified:       make(map[string]*notificationState),
		lastChangeNotified: make(map[string]time.Time),
		pendingTimers:      make(map[string]*time.Timer),
	}
}

// Send sends a notification with 2-second debouncing
// Ensures minimum 2-second interval between notifications for rapid state cycling
func (n *Notifier) Send(labName, message string) {
	if n == nil {
		return // No-op if notifier is disabled
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()
	state, exists := n.lastNotified[labName]

	// Skip if same message as last notification
	if exists && state.lastMessage == message {
		return
	}

	// Check if we're within the 2-second debounce interval
	if exists && time.Since(state.lastTime) < 2*time.Second {
		// Cancel any existing pending timer
		if timer, hasTimer := n.pendingTimers[labName]; hasTimer {
			timer.Stop()
		}

		// Store the message as pending
		state.pending = message

		// Schedule delivery after remaining interval
		remaining := 2*time.Second - time.Since(state.lastTime)
		n.pendingTimers[labName] = time.AfterFunc(remaining, func() {
			n.deliverPending(labName)
		})

		return
	}

	// Send immediately - no debounce needed
	n.lastNotified[labName] = &notificationState{
		lastMessage: message,
		lastTime:    now,
	}

	// Reset the watch-triggered cooldown when a state transition occurs
	delete(n.lastChangeNotified, labName)

	// Fan-out to all SSE subscribers
	n.fanOut(message)
}

// deliverPending delivers a pending notification after debounce interval
func (n *Notifier) deliverPending(labName string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	state, exists := n.lastNotified[labName]
	if !exists || state.pending == "" {
		return
	}

	message := state.pending
	state.pending = ""
	state.lastMessage = message
	state.lastTime = time.Now()

	// Clean up timer
	delete(n.pendingTimers, labName)

	// Reset the watch-triggered cooldown
	delete(n.lastChangeNotified, labName)

	// Fan-out to all SSE subscribers
	n.fanOut(message)
}

// SendChange sends a notification with 30-second cooldown deduplication
// Used for "Change detected" notifications to avoid spam
func (n *Notifier) SendChange(labName, message string) {
	if n == nil {
		return // No-op if notifier is disabled
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Implement 30-second cooldown
	lastNotify := n.lastChangeNotified[labName]
	if time.Since(lastNotify) <= 30*time.Second {
		return // Still in cooldown period
	}

	// Update cooldown timestamp
	n.lastChangeNotified[labName] = time.Now()

	// Fan-out to all SSE subscribers
	n.fanOut(message)
}

// Subscribe registers a new SSE client and returns a channel and cleanup function
// Immediately sends the current state to the new client
func (n *Notifier) Subscribe() (<-chan string, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextID
	n.nextID++

	ch := make(chan string, 10) // Buffered to prevent slow clients from blocking
	n.subscribers[id] = ch

	// Send current state to new subscriber immediately
	// This ensures users see the current lab status when they refresh the page
	for _, state := range n.lastNotified {
		if state.lastMessage != "" {
			select {
			case ch <- state.lastMessage:
				// Sent successfully
			default:
				// Channel shouldn't be full on first message, but handle gracefully
				ctrl.Log.WithName("notifier").Info("Could not send initial state to new client")
			}
			// Only send one message (the most recent lab state)
			break
		}
	}

	cleanup := func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		delete(n.subscribers, id)
		close(ch)
	}

	return ch, cleanup
}

// fanOut sends a message to all subscribed SSE clients
// Must be called with lock held
func (n *Notifier) fanOut(message string) {
	for _, ch := range n.subscribers {
		select {
		case ch <- message:
			// Sent successfully
		default:
			// Channel is full, skip (don't block reconciliation)
			ctrl.Log.WithName("notifier").Info("Skipped notification to slow client")
		}
	}
}
