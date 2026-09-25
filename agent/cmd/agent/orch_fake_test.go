package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/TrafficWrapper/worker/agent/internal/protocol"
	"github.com/flynn/noise"
)

// fakeOrchestrator answers the Noise XK worker API like the orchestrator
// does, so tests can exercise orchClient end to end. handle receives the
// decrypted request for a /w/v1/* path and returns the value to encrypt.
type fakeOrchestrator struct {
	t      *testing.T
	server *httptest.Server
	key    noise.DHKey
	handle func(path string, req json.RawMessage) any

	// cookie, when set, is returned in the outer envelope of every
	// successful /w/v1/* response, like the orchestrator's handshake cookie.
	cookie string

	mu       sync.Mutex
	sessions map[string]*noise.HandshakeState
	requests map[string][]json.RawMessage
	starts   []json.RawMessage
}

func newFakeOrchestrator(t *testing.T, handle func(path string, req json.RawMessage) any) *fakeOrchestrator {
	t.Helper()
	key, err := protocol.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOrchestrator{t: t, key: key, handle: handle, sessions: map[string]*noise.HandshakeState{}, requests: map[string][]json.RawMessage{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeOrchestrator) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/w/v1/handshake/start" {
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		var req orchStartRequest
		_ = json.Unmarshal(raw, &req)
		f.mu.Lock()
		f.starts = append(f.starts, raw)
		f.mu.Unlock()
		hs, err := noise.NewHandshakeState(noise.Config{
			CipherSuite:   protocol.CipherSuite(),
			Pattern:       noise.HandshakeXK,
			Prologue:      []byte(orchestratorPrologue),
			StaticKeypair: f.key,
		})
		if err != nil {
			f.t.Error(err)
			return
		}
		msg1, _ := base64.StdEncoding.DecodeString(req.Message)
		if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
			writeJSON(w, orchStartResponse{Error: err.Error()})
			return
		}
		msg2, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			f.t.Error(err)
			return
		}
		f.mu.Lock()
		sid := randHex(8)
		f.sessions[sid] = hs
		f.mu.Unlock()
		writeJSON(w, orchStartResponse{OK: true, SID: sid, Message: base64.StdEncoding.EncodeToString(msg2)})
		return
	}
	var env orchEnvelope
	_ = json.NewDecoder(r.Body).Decode(&env)
	f.mu.Lock()
	hs := f.sessions[env.SID]
	delete(f.sessions, env.SID)
	f.mu.Unlock()
	if hs == nil {
		writeJSON(w, orchEnvelopeResponse{Error: "unknown session"})
		return
	}
	msg3, _ := base64.StdEncoding.DecodeString(env.Message)
	_, recvCipher, sendCipher, err := hs.ReadMessage(nil, msg3)
	if err != nil {
		writeJSON(w, orchEnvelopeResponse{Error: err.Error()})
		return
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	var req json.RawMessage
	if err := protocol.DecryptJSON(recvCipher, payload, &req); err != nil {
		writeJSON(w, orchEnvelopeResponse{Error: err.Error()})
		return
	}
	f.mu.Lock()
	f.requests[r.URL.Path] = append(f.requests[r.URL.Path], req)
	f.mu.Unlock()
	encrypted, err := protocol.EncryptJSON(sendCipher, f.handle(r.URL.Path, req))
	if err != nil {
		f.t.Error(err)
		return
	}
	f.mu.Lock()
	cookie := f.cookie
	f.mu.Unlock()
	writeJSON(w, orchEnvelopeResponse{OK: true, Payload: base64.StdEncoding.EncodeToString(encrypted), Cookie: cookie})
}

// requestsTo returns the decrypted requests the fake received on path.
func (f *fakeOrchestrator) requestsTo(path string) []json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]json.RawMessage(nil), f.requests[path]...)
}

// startRequests returns the raw handshake start bodies the fake received.
func (f *fakeOrchestrator) startRequests() []json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]json.RawMessage(nil), f.starts...)
}

// setCookie changes the handshake cookie the fake hands out.
func (f *fakeOrchestrator) setCookie(v string) {
	f.mu.Lock()
	f.cookie = v
	f.mu.Unlock()
}

// client returns an orchClient for a fresh worker identity talking to f.
func (f *fakeOrchestrator) client(cfg envConfig) *orchClient {
	f.t.Helper()
	workerKey, err := protocol.GenerateKeypair()
	if err != nil {
		f.t.Fatal(err)
	}
	cfg.OrchURL = f.server.URL
	cfg.OrchStaticPublic = protocol.KeyToBase64(f.key.Public)
	kp := protocol.NewKeyPairFile(workerKey)
	st := stateFile{}
	st.NoiseStatic.PrivateKey = kp.PrivateKey
	st.NoiseStatic.PublicKey = kp.PublicKey
	c, err := newOrchClient(cfg, st)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func TestFakeOrchestratorRoundTrip(t *testing.T) {
	f := newFakeOrchestrator(t, func(path string, _ json.RawMessage) any {
		return map[string]any{"ok": true, "status": "active", "desired_seq": 7, "path": path}
	})
	resp, err := f.client(envConfig{}).pull(t.Context(), "w1", 3)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.DesiredSeq != 7 {
		t.Fatalf("pull response: %+v", resp)
	}
	if got := f.requestsTo("/w/v1/config/pull"); len(got) != 1 || !strings.Contains(string(got[0]), `"have_seq":3`) {
		t.Fatalf("pull requests: %s", got)
	}
}
