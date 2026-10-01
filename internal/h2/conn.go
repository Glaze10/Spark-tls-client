// Package h2 is a small HTTP/2 client connection whose opening is fully dictated by
// a profile: SETTINGS entries and their order, the connection WINDOW_UPDATE, any
// PRIORITY frames, the HEADERS priority block and the pseudo-header order.
//
// golang.org/x/net/http2's Transport decides all of those itself, which is the
// reason every Go client that wants a browser's HTTP/2 fingerprint ends up on a fork
// of it. Here we use only its Framer and hpack, and own the protocol logic.
package h2

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/leosm/spark-tls/profile"
)

const (
	defaultWindow    = 65535
	defaultMaxFrame  = 16384
	maxReadFrameSize = 1<<24 - 1
)

// ErrConnClosed means the connection can't take new streams; dial a new one.
var ErrConnClosed = errors.New("h2: connection closed")

// Header is one header field, order preserved.
type Header struct{ Name, Value string }

type Request struct {
	Method    string
	Authority string
	Scheme    string
	Path      string
	Headers   []Header
	Body      []byte
}

type Response struct {
	Status   int
	Headers  []Header
	Trailers []Header
	Body     []byte
}

type stream struct {
	id         uint32
	sendWindow int32
	recvUnack  int32
	resp       Response
	gotHeaders bool
	done       chan struct{}
	err        error
}

type Conn struct {
	nc  net.Conn
	bw  *bufio.Writer
	fr  *http2.Framer
	enc *hpack.Encoder
	eb  bytes.Buffer
	wmu sync.Mutex // serialises frame writes and keeps hpack state in wire order

	mu             sync.Mutex
	cond           *sync.Cond
	streams        map[uint32]*stream
	nextID         uint32
	closed         bool
	goAway         bool
	err            error
	peerMaxFrame   uint32
	peerInitWindow int32
	peerMaxStreams uint32
	connSendWindow int32
	connRecvUnack  int32
	localStreamWin int32
	localConnWin   int32
	lastUsed       time.Time

	pseudo []string
	prio   *profile.Priority
}

// NewConn writes the client preface described by p onto nc (already TLS-negotiated
// to h2) and starts the read loop.
func NewConn(nc net.Conn, p *profile.H2) (*Conn, error) {
	if p == nil {
		p = &profile.H2{}
	}
	c := &Conn{
		nc:             nc,
		bw:             bufio.NewWriterSize(nc, 32<<10),
		streams:        map[uint32]*stream{},
		nextID:         1,
		peerMaxFrame:   defaultMaxFrame,
		peerInitWindow: defaultWindow,
		peerMaxStreams: 100,
		connSendWindow: defaultWindow,
		localStreamWin: defaultWindow,
		localConnWin:   defaultWindow + int32(p.ConnectionWindowUpdate),
		lastUsed:       time.Now(),
		prio:           p.HeaderPriority,
	}
	c.cond = sync.NewCond(&c.mu)
	c.fr = http2.NewFramer(c.bw, bufio.NewReaderSize(nc, 32<<10))
	c.fr.SetMaxReadFrameSize(maxReadFrameSize)
	c.enc = hpack.NewEncoder(&c.eb)

	headerTable := uint32(4096)
	var maxHeaderList uint32
	settings := make([]http2.Setting, 0, len(p.Settings))
	for _, s := range p.Settings {
		settings = append(settings, http2.Setting{ID: http2.SettingID(s.ID), Val: s.Value})
		switch http2.SettingID(s.ID) {
		case http2.SettingInitialWindowSize:
			c.localStreamWin = int32(s.Value)
		case http2.SettingHeaderTableSize:
			headerTable = s.Value
		case http2.SettingMaxHeaderListSize:
			maxHeaderList = s.Value
		}
	}
	c.fr.ReadMetaHeaders = hpack.NewDecoder(headerTable, nil)
	if maxHeaderList > 0 {
		c.fr.MaxHeaderListSize = maxHeaderList
	} else {
		c.fr.MaxHeaderListSize = 1 << 20
	}
	c.pseudo = p.PseudoOrder
	if len(c.pseudo) != 4 {
		c.pseudo = []string{":method", ":authority", ":scheme", ":path"}
	}

	if _, err := c.bw.WriteString(http2.ClientPreface); err != nil {
		return nil, err
	}
	if err := c.fr.WriteSettings(settings...); err != nil {
		return nil, err
	}
	if p.ConnectionWindowUpdate > 0 {
		if err := c.fr.WriteWindowUpdate(0, p.ConnectionWindowUpdate); err != nil {
			return nil, err
		}
	}
	for _, pf := range p.PriorityFrames {
		err := c.fr.WritePriority(pf.StreamID, http2.PriorityParam{
			StreamDep: pf.Priority.StreamDep, Exclusive: pf.Priority.Exclusive, Weight: pf.Priority.Weight,
		})
		if err != nil {
			return nil, err
		}
		if pf.StreamID >= c.nextID {
			c.nextID = pf.StreamID + 2 - pf.StreamID%2
		}
	}
	if err := c.bw.Flush(); err != nil {
		return nil, err
	}
	go c.readLoop()
	return c, nil
}

// CanTakeRequest reports whether a new stream may be opened on this connection.
func (c *Conn) CanTakeRequest() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && !c.goAway && c.nextID < 1<<31-1
}

// IdleSince returns when the connection last finished a request, or zero if busy.
func (c *Conn) IdleSince() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.streams) > 0 {
		return time.Time{}
	}
	return c.lastUsed
}

func (c *Conn) Close() error {
	c.fail(ErrConnClosed)
	return c.nc.Close()
}

// RoundTrip sends one request and waits for the whole response.
func (c *Conn) RoundTrip(ctx context.Context, req *Request) (*Response, error) {
	c.mu.Lock()
	for !c.closed && !c.goAway && uint32(len(c.streams)) >= c.peerMaxStreams {
		c.waitCtx(ctx)
		if ctx.Err() != nil {
			c.mu.Unlock()
			return nil, ctx.Err()
		}
	}
	c.mu.Unlock()

	st, err := c.openStream(req)
	if err != nil {
		if st != nil {
			c.endStream(st, err)
		}
		return nil, err
	}
	if len(req.Body) > 0 {
		if err := c.writeBody(ctx, st, req.Body); err != nil {
			c.resetStream(st, http2.ErrCodeCancel)
			c.endStream(st, err)
			return nil, err
		}
	}

	select {
	case <-st.done:
		if st.err != nil {
			return nil, st.err
		}
		return &st.resp, nil
	case <-ctx.Done():
		c.resetStream(st, http2.ErrCodeCancel)
		c.endStream(st, ctx.Err())
		return nil, ctx.Err()
	}
}

// waitCtx waits on cond but wakes if ctx ends. Caller holds c.mu.
func (c *Conn) waitCtx(ctx context.Context) {
	stop := context.AfterFunc(ctx, func() {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	c.cond.Wait()
	stop()
}

// connection-specific headers are illegal in HTTP/2 (RFC 9113 8.2.2).
var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true,
	"transfer-encoding": true, "upgrade": true, "host": true,
}

// openStream allocates a stream ID and writes its HEADERS in one critical section.
// Allocating earlier would let two goroutines put their HEADERS on the wire out of
// ID order, and a server must treat a lower ID arriving late as a protocol error.
//
// Lock order: wmu, then mu. Nothing takes wmu while holding mu.
func (c *Conn) openStream(req *Request) (*stream, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	c.mu.Lock()
	if c.closed || c.goAway {
		c.mu.Unlock()
		return nil, ErrConnClosed
	}
	st := &stream{
		id:         c.nextID,
		sendWindow: c.peerInitWindow,
		done:       make(chan struct{}),
	}
	c.nextID += 2
	c.streams[st.id] = st
	maxFrame := int(c.peerMaxFrame)
	c.mu.Unlock()

	return st, c.writeHeaders(st, req, maxFrame)
}

// writeHeaders encodes and sends the header block. Caller holds wmu.
func (c *Conn) writeHeaders(st *stream, req *Request, maxFrame int) error {

	c.eb.Reset()
	for _, p := range c.pseudo {
		var v string
		switch p {
		case ":method":
			v = req.Method
		case ":authority":
			v = req.Authority
		case ":scheme":
			v = req.Scheme
		case ":path":
			v = req.Path
		}
		c.enc.WriteField(hpack.HeaderField{Name: p, Value: v})
	}
	for _, h := range req.Headers {
		name := strings.ToLower(h.Name)
		if hopByHop[name] || strings.HasPrefix(name, ":") {
			continue
		}
		if name == "te" && h.Value != "trailers" {
			continue
		}
		c.enc.WriteField(hpack.HeaderField{Name: name, Value: h.Value})
	}
	block := c.eb.Bytes()

	first := block
	if len(first) > maxFrame {
		first = block[:maxFrame]
	}
	rest := block[len(first):]
	param := http2.HeadersFrameParam{
		StreamID:      st.id,
		BlockFragment: first,
		EndStream:     len(req.Body) == 0,
		EndHeaders:    len(rest) == 0,
	}
	if c.prio != nil {
		param.Priority = http2.PriorityParam{
			StreamDep: c.prio.StreamDep, Exclusive: c.prio.Exclusive, Weight: c.prio.Weight,
		}
	}
	if err := c.fr.WriteHeaders(param); err != nil {
		return err
	}
	for len(rest) > 0 {
		chunk := rest
		if len(chunk) > maxFrame {
			chunk = rest[:maxFrame]
		}
		rest = rest[len(chunk):]
		if err := c.fr.WriteContinuation(st.id, len(rest) == 0, chunk); err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

func (c *Conn) writeBody(ctx context.Context, st *stream, body []byte) error {
	for len(body) > 0 {
		c.mu.Lock()
		for c.err == nil && st.err == nil && (c.connSendWindow <= 0 || st.sendWindow <= 0) {
			c.waitCtx(ctx)
			if ctx.Err() != nil {
				c.mu.Unlock()
				return ctx.Err()
			}
		}
		if c.err != nil {
			c.mu.Unlock()
			return c.err
		}
		if st.err != nil {
			c.mu.Unlock()
			return st.err
		}
		n := min(int32(len(body)), c.connSendWindow, st.sendWindow, int32(c.peerMaxFrame))
		c.connSendWindow -= n
		st.sendWindow -= n
		c.mu.Unlock()

		chunk := body[:n]
		body = body[n:]
		c.wmu.Lock()
		err := c.fr.WriteData(st.id, len(body) == 0, chunk)
		if err == nil {
			err = c.bw.Flush()
		}
		c.wmu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) resetStream(st *stream, code http2.ErrCode) {
	c.wmu.Lock()
	c.fr.WriteRSTStream(st.id, code)
	c.bw.Flush()
	c.wmu.Unlock()
}

func (c *Conn) endStream(st *stream, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.streams[st.id]; !ok {
		return
	}
	delete(c.streams, st.id)
	st.err = err
	c.lastUsed = time.Now()
	close(st.done)
	c.cond.Broadcast()
}

func (c *Conn) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.err = err
	for id, st := range c.streams {
		delete(c.streams, id)
		st.err = err
		close(st.done)
	}
	c.cond.Broadcast()
}

func (c *Conn) readLoop() {
	var err error
	for {
		var f http2.Frame
		f, err = c.fr.ReadFrame()
		if err != nil {
			break
		}
		if err = c.handle(f); err != nil {
			break
		}
	}
	if errors.Is(err, io.EOF) {
		err = ErrConnClosed
	}
	c.fail(fmt.Errorf("h2: %w", err))
	c.nc.Close()
}

func (c *Conn) stream(id uint32) *stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

func (c *Conn) handle(f http2.Frame) error {
	switch f := f.(type) {
	case *http2.MetaHeadersFrame:
		st := c.stream(f.StreamID)
		if st == nil {
			return nil
		}
		if !st.gotHeaders {
			code, err := strconv.Atoi(f.PseudoValue("status"))
			if err != nil {
				c.resetStream(st, http2.ErrCodeProtocol)
				c.endStream(st, fmt.Errorf("h2: bad :status %q", f.PseudoValue("status")))
				return nil
			}
			if code >= 100 && code < 200 {
				return nil // informational; the real response follows
			}
			st.gotHeaders = true
			st.resp.Status = code
			st.resp.Headers = regular(f.Fields)
		} else {
			st.resp.Trailers = regular(f.Fields)
		}
		if f.StreamEnded() {
			c.endStream(st, nil)
		}

	case *http2.DataFrame:
		// Flow control counts the whole frame, padding included.
		if n := int32(f.Length); n > 0 {
			c.consumed(f.StreamID, n)
		}
		st := c.stream(f.StreamID)
		if st == nil {
			return nil
		}
		st.resp.Body = append(st.resp.Body, f.Data()...)
		if f.StreamEnded() {
			c.endStream(st, nil)
		}

	case *http2.SettingsFrame:
		if f.IsAck() {
			return nil
		}
		var tableSize uint32
		var tableSet bool
		c.mu.Lock()
		err := f.ForeachSetting(func(s http2.Setting) error {
			switch s.ID {
			case http2.SettingMaxFrameSize:
				c.peerMaxFrame = s.Val
			case http2.SettingMaxConcurrentStreams:
				c.peerMaxStreams = s.Val
			case http2.SettingInitialWindowSize:
				delta := int32(s.Val) - c.peerInitWindow
				for _, st := range c.streams {
					st.sendWindow += delta
				}
				c.peerInitWindow = int32(s.Val)
			case http2.SettingHeaderTableSize:
				tableSize = s.Val
				tableSet = true
			}
			return nil
		})
		c.cond.Broadcast()
		c.mu.Unlock()
		if err != nil {
			return err
		}
		c.wmu.Lock()
		defer c.wmu.Unlock()
		if tableSet {
			c.enc.SetMaxDynamicTableSizeLimit(tableSize)
		}
		if err := c.fr.WriteSettingsAck(); err != nil {
			return err
		}
		return c.bw.Flush()

	case *http2.WindowUpdateFrame:
		c.mu.Lock()
		if f.StreamID == 0 {
			c.connSendWindow += int32(f.Increment)
		} else if st := c.streams[f.StreamID]; st != nil {
			st.sendWindow += int32(f.Increment)
		}
		c.cond.Broadcast()
		c.mu.Unlock()

	case *http2.PingFrame:
		if f.IsAck() {
			return nil
		}
		c.wmu.Lock()
		defer c.wmu.Unlock()
		if err := c.fr.WritePing(true, f.Data); err != nil {
			return err
		}
		return c.bw.Flush()

	case *http2.RSTStreamFrame:
		if st := c.stream(f.StreamID); st != nil {
			c.endStream(st, http2.StreamError{StreamID: f.StreamID, Code: f.ErrCode})
		}

	case *http2.GoAwayFrame:
		c.mu.Lock()
		c.goAway = true
		var orphans []*stream
		for id, st := range c.streams {
			if id > f.LastStreamID {
				orphans = append(orphans, st)
			}
		}
		c.cond.Broadcast()
		c.mu.Unlock()
		for _, st := range orphans {
			c.endStream(st, fmt.Errorf("h2: server sent GOAWAY (%v); request not processed", f.ErrCode))
		}

	case *http2.PushPromiseFrame:
		// We advertise push disabled; a server that pushes anyway gets refused.
		c.wmu.Lock()
		c.fr.WriteRSTStream(f.PromiseID, http2.ErrCodeRefusedStream)
		c.bw.Flush()
		c.wmu.Unlock()
	}
	return nil
}

// consumed credits received DATA back to the peer once half a window is used,
// which is when Chrome sends its WINDOW_UPDATEs too.
func (c *Conn) consumed(streamID uint32, n int32) {
	c.mu.Lock()
	c.connRecvUnack += n
	var connInc, streamInc int32
	if c.connRecvUnack >= c.localConnWin/2 {
		connInc, c.connRecvUnack = c.connRecvUnack, 0
	}
	if st := c.streams[streamID]; st != nil {
		st.recvUnack += n
		if st.recvUnack >= c.localStreamWin/2 {
			streamInc, st.recvUnack = st.recvUnack, 0
		}
	}
	c.mu.Unlock()
	if connInc == 0 && streamInc == 0 {
		return
	}
	c.wmu.Lock()
	if connInc > 0 {
		c.fr.WriteWindowUpdate(0, uint32(connInc))
	}
	if streamInc > 0 {
		c.fr.WriteWindowUpdate(streamID, uint32(streamInc))
	}
	c.bw.Flush()
	c.wmu.Unlock()
}

func regular(fields []hpack.HeaderField) []Header {
	out := make([]Header, 0, len(fields))
	for _, f := range fields {
		if !f.IsPseudo() {
			out = append(out, Header{f.Name, f.Value})
		}
	}
	return out
}

// ToHTTPHeader is a convenience for callers that want net/http's map form.
func ToHTTPHeader(hs []Header) http.Header {
	h := http.Header{}
	for _, f := range hs {
		h.Add(f.Name, f.Value)
	}
	return h
}
