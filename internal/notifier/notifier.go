package notifier

import (
	"sync"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

// Event represents a single notification delivered to SSE clients.
type Event struct {
	Message       string    `json:"message"`
	Kind          string    `json:"kind,omitempty"`
	ChallengeID   string    `json:"challengeId,omitempty"`
	Vulnerability string    `json:"vulnerability,omitempty"`
	SubIssue      *int      `json:"subIssue,omitempty"`
	Lab           string    `json:"lab,omitempty"`
	SentAt        time.Time `json:"sentAt"`
}

// Notifier handles sending notifications to SSE clients
type Notifier struct {
	mu                 sync.RWMutex
	subscribers        map[int]chan Event
	nextID             int
	lastNotified       map[string]*notificationState
	lastChangeNotified map[string]time.Time
	pendingTimers      map[string]*time.Timer
}

// notificationState tracks the last notification sent for a lab
type notificationState struct {
	lastEvent Event
	lastTime  time.Time
	pending   *Event // Pending event to deliver after debounce interval
}

// New creates a new Notifier instance
func New() *Notifier {
	return &Notifier{
		subscribers:        make(map[int]chan Event),
		lastNotified:       make(map[string]*notificationState),
		lastChangeNotified: make(map[string]time.Time),
		pendingTimers:      make(map[string]*time.Timer),
	}
}

// SendEvent sends a structured notification with 2-second debouncing.
// Ensures minimum 2-second interval between notifications for rapid state cycling.
func (n *Notifier) SendEvent(labName string, event Event) {
	if n == nil {
		return // No-op if notifier is disabled
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()
	event = normalizeEvent(labName, event, now)
	state, exists := n.lastNotified[labName]

	// Skip if same message as last notification
	if exists && sameLogicalEvent(state.lastEvent, event) {
		return
	}

	// Check if we're within the 2-second debounce interval
	if exists && time.Since(state.lastTime) < 2*time.Second {
		// Cancel any existing pending timer
		if timer, hasTimer := n.pendingTimers[labName]; hasTimer {
			timer.Stop()
		}

		// Store the event as pending
		pending := event
		state.pending = &pending

		// Schedule delivery after remaining interval
		remaining := 2*time.Second - time.Since(state.lastTime)
		n.pendingTimers[labName] = time.AfterFunc(remaining, func() {
			n.deliverPending(labName)
		})

		return
	}

	// Send immediately - no debounce needed
	n.lastNotified[labName] = &notificationState{
		lastEvent: event,
		lastTime:  now,
	}

	// Reset the watch-triggered cooldown when a state transition occurs
	delete(n.lastChangeNotified, labName)

	// Fan-out to all SSE subscribers
	n.fanOut(event)
}

// deliverPending delivers a pending notification after debounce interval
func (n *Notifier) deliverPending(labName string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	state, exists := n.lastNotified[labName]
	if !exists || state.pending == nil {
		return
	}

	event := *state.pending
	state.pending = nil
	state.lastEvent = event
	state.lastTime = time.Now()

	// Clean up timer
	delete(n.pendingTimers, labName)

	// Reset the watch-triggered cooldown
	delete(n.lastChangeNotified, labName)

	// Fan-out to all SSE subscribers
	n.fanOut(event)
}

// SendChangeEvent sends a structured notification with 30-second cooldown deduplication.
// Used for "Change detected" notifications to avoid spam.
func (n *Notifier) SendChangeEvent(labName string, event Event) {
	if n == nil {
		return // No-op if notifier is disabled
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	event = normalizeEvent(labName, event, time.Now())

	// Implement 30-second cooldown
	lastNotify := n.lastChangeNotified[labName]
	if time.Since(lastNotify) <= 30*time.Second {
		return // Still in cooldown period
	}

	// Update cooldown timestamp
	n.lastChangeNotified[labName] = time.Now()

	// Fan-out to all SSE subscribers
	n.fanOut(event)
}

// Subscribe registers a new SSE client and returns a channel and cleanup function
// Immediately sends the current state to the new client
func (n *Notifier) Subscribe() (<-chan Event, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.nextID
	n.nextID++

	ch := make(chan Event, 10) // Buffered to prevent slow clients from blocking
	n.subscribers[id] = ch

	// Send current state to new subscriber immediately
	// This ensures users see the current lab status when they refresh the page
	for _, state := range n.lastNotified {
		if state.lastEvent.Message != "" {
			select {
			case ch <- state.lastEvent:
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
func (n *Notifier) fanOut(event Event) {
	for _, ch := range n.subscribers {
		select {
		case ch <- event:
			// Sent successfully
		default:
			// Channel is full, skip (don't block reconciliation)
			ctrl.Log.WithName("notifier").Info("Skipped notification to slow client")
		}
	}
}

func normalizeEvent(labName string, event Event, now time.Time) Event {
	if event.Lab == "" {
		event.Lab = labName
	}
	if event.SentAt.IsZero() {
		event.SentAt = now
	}
	return event
}

func sameLogicalEvent(a, b Event) bool {
	return a.Message == b.Message && a.ChallengeID == b.ChallengeID
}
