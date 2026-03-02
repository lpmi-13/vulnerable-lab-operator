package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

// Server implements manager.Runnable to serve SSE notifications
type Server struct {
	notifier *Notifier
	port     int
	server   *http.Server
}

// NewServer creates a new SSE notification server
func NewServer(notifier *Notifier, port int) *Server {
	return &Server{
		notifier: notifier,
		port:     port,
	}
}

// Start implements manager.Runnable interface
func (s *Server) Start(ctx context.Context) error {
	logger := ctrl.Log.WithName("notifier-server")

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/events", s.handleEvents)

	s.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("Starting notification server", "port", s.port, "url", fmt.Sprintf("http://localhost:%d", s.port))

	// Run server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		logger.Info("Shutting down notification server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// handleRoot serves the HTML page with SSE client
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Cluster Notifications</title>
    <style>
        body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; margin: 0; }
        h1 { color: #4ec9b0; margin-bottom: 10px; }
        #status { color: #ce9178; margin-bottom: 20px; }
        .notification {
            --accent: #4ec9b0;
            --bg: #2d2d30;
            background: var(--bg);
            border-left: 4px solid var(--accent);
            padding: 12px 16px;
            margin: 8px 0;
            border-radius: 4px;
            animation: slideIn 0.3s ease-out;
        }
        .notification.new {
            animation: slideIn 0.3s ease-out, pulseIn 1.8s ease-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        @keyframes pulseIn {
            0% { box-shadow: 0 0 0 rgba(0, 0, 0, 0); }
            20% { box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 35%, transparent); }
            100% { box-shadow: 0 0 0 rgba(0, 0, 0, 0); }
        }
        .timestamp { color: #858585; font-size: 0.9em; margin-right: 8px; }
        .message { color: #dcdcaa; }
        #notifications { max-height: 80vh; overflow-y: auto; }
    </style>
</head>
<body>
    <h1>Cluster Notification Feed</h1>
    <div id="status">Connecting to event stream...</div>
    <div id="notifications"></div>
    <script>
        const statusDiv = document.getElementById('status');
        const notificationsDiv = document.getElementById('notifications');
        const originalTitle = document.title;
        let titleFlashInterval = null;
        const colorByChallenge = new Map();
        const palette = [
            { accent: '#4ec9b0', bg: '#243734' },
            { accent: '#569cd6', bg: '#1f3345' },
            { accent: '#d7ba7d', bg: '#3c3422' },
            { accent: '#c586c0', bg: '#3a2a3d' },
            { accent: '#9cdc6f', bg: '#2b3c24' },
            { accent: '#ce9178', bg: '#3d2d27' }
        ];

        // Request notification permission on page load
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }

        // Title flashing function
        function startTitleFlash(message) {
            if (titleFlashInterval) return; // Already flashing
            let showingAlert = true;
            titleFlashInterval = setInterval(() => {
                document.title = showingAlert ? '(*) New Notification' : originalTitle;
                showingAlert = !showingAlert;
            }, 1000);
        }

        function stopTitleFlash() {
            if (titleFlashInterval) {
                clearInterval(titleFlashInterval);
                titleFlashInterval = null;
                document.title = originalTitle;
            }
        }

        function colorForChallenge(challengeId) {
            const key = challengeId || 'unclassified';
            if (!colorByChallenge.has(key)) {
                colorByChallenge.set(key, palette[colorByChallenge.size % palette.length]);
            }
            return colorByChallenge.get(key);
        }

        function normalizePayload(raw) {
            let parsed = raw;
            try {
                parsed = JSON.parse(raw);
            } catch (_) {
                return { message: raw, challengeId: 'unclassified' };
            }

            if (typeof parsed === 'string') {
                return { message: parsed, challengeId: 'unclassified' };
            }

            if (!parsed || typeof parsed !== 'object') {
                return { message: String(raw), challengeId: 'unclassified' };
            }

            const message = (typeof parsed.message === 'string' && parsed.message) ||
                (typeof parsed.Message === 'string' && parsed.Message) ||
                String(raw);
            const challengeId = (typeof parsed.challengeId === 'string' && parsed.challengeId) ||
                (typeof parsed.ChallengeID === 'string' && parsed.ChallengeID) ||
                'unclassified';

            return { message, challengeId };
        }

        // Stop flashing when tab regains focus
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                stopTitleFlash();
            }
        });

        const eventSource = new EventSource('/events');

        eventSource.onopen = () => {
            statusDiv.textContent = 'Connected - waiting for notifications...';
            statusDiv.style.color = '#4ec9b0';
        };

        eventSource.onmessage = (event) => {
            const payload = normalizePayload(event.data);
            const colors = colorForChallenge(payload.challengeId);
            const notification = document.createElement('div');
            notification.className = 'notification new';
            notification.style.setProperty('--accent', colors.accent);
            notification.style.setProperty('--bg', colors.bg);

            const timestamp = document.createElement('span');
            timestamp.className = 'timestamp';
            timestamp.textContent = new Date().toLocaleTimeString();

            const message = document.createElement('span');
            message.className = 'message';
            message.textContent = payload.message;

            notification.appendChild(timestamp);
            notification.appendChild(message);

            notificationsDiv.insertBefore(notification, notificationsDiv.firstChild);

            setTimeout(() => notification.classList.remove('new'), 2000);

            // Keep only last 50 notifications
            while (notificationsDiv.children.length > 50) {
                notificationsDiv.removeChild(notificationsDiv.lastChild);
            }

            // Background tab notifications
            if (document.hidden) {
                // Browser notification popup
                if ('Notification' in window && Notification.permission === 'granted') {
                    const n = new Notification('Cluster Notification', {
                        body: payload.message,
                        icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y="75" font-size="75">🔔</text></svg>'
                    });
                    n.onclick = () => {
                        window.focus();
                        n.close();
                    };
                }

                // Title flashing
                startTitleFlash(payload.message);
            }
        };

        eventSource.onerror = () => {
            statusDiv.textContent = 'Connection lost - retrying...';
            statusDiv.style.color = '#f48771';
        };
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// handleEvents serves the SSE event stream
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	logger := ctrl.Log.WithName("sse")

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Subscribe to notifications
	msgChan, cleanup := s.notifier.Subscribe()
	defer cleanup()

	logger.Info("New SSE client connected")

	// Stream notifications until client disconnects
	for {
		select {
		case <-r.Context().Done():
			logger.Info("SSE client disconnected")
			return
		case msg, ok := <-msgChan:
			if !ok {
				return // Channel closed
			}
			payload, err := json.Marshal(msg)
			if err != nil {
				logger.Error(err, "Failed to serialize notification event")
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				logger.Error(err, "Failed to write message")
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}
