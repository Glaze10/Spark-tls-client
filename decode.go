package sparktls

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// decompress undoes Content-Encoding, applying codings in reverse order.
func decompress(header string, body []byte) ([]byte, error) {
	codings := strings.Split(header, ",")
	for i := len(codings) - 1; i >= 0; i-- {
		var err error
		switch strings.TrimSpace(strings.ToLower(codings[i])) {
		case "gzip", "x-gzip":
			var r *gzip.Reader
			if r, err = gzip.NewReader(bytes.NewReader(body)); err == nil {
				body, err = io.ReadAll(r)
			}
		case "deflate":
			// "deflate" is zlib-wrapped by spec, but some servers send raw deflate.
			var r io.ReadCloser
			if r, err = zlib.NewReader(bytes.NewReader(body)); err == nil {
				body, err = io.ReadAll(r)
			} else {
				body, err = io.ReadAll(flate.NewReader(bytes.NewReader(body)))
			}
		case "br":
			body, err = io.ReadAll(brotli.NewReader(bytes.NewReader(body)))
		case "zstd":
			var d *zstd.Decoder
			if d, err = zstd.NewReader(nil); err == nil {
				body, err = d.DecodeAll(body, nil)
				d.Close()
			}
		case "identity", "":
		default:
			return nil, fmt.Errorf("unknown content-encoding %q", codings[i])
		}
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}
