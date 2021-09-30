package gosshacl

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aurora-is-near/sshaclsrv/src/constants"

	"github.com/aurora-is-near/sshaclsrv/src/delegatesign"
)

var (
	// ErrFallback is returned if processing should continue with a different backend.
	ErrFallback = errors.New("fallback")
)

// RemoteACL calls a remote HTTP(s) server to find keys.
type RemoteACL struct {
	URL       string            // https://<url>/keyFP/hostname/user/
	PublicKey ed25519.PublicKey // Master Publickey.
	Token     string            // http-basic auth password, hostname is user.
	Hostname  string            // Server's hostname.
}

// NewRemote returns a new RemoteACL that uses the given url. If token is not empty it will
// be used as username in BasicAuth (password default). The public key will be used to verify the entry signatures.
func NewRemote(url string, publicKey ed25519.PublicKey, token, hostname string) *RemoteACL {
	if url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	return &RemoteACL{
		PublicKey: publicKey,
		Token:     token,
		URL:       url,
		Hostname:  hostname,
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func httpclient(timeout time.Duration) *http.Client {
	timeout = minDuration(time.Second*5, timeout)
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives:      true,
			DisableCompression:     true,
			MaxResponseHeaderBytes: 4096,
			Proxy:                  http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: timeout,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       timeout,
			TLSHandshakeTimeout:   minDuration(time.Second, timeout-time.Second),
			ExpectContinueTimeout: minDuration(time.Second, timeout-time.Second*2),
		},
	}
}

func getURL(c *http.Client, url, hostname, token string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, ErrFallback
	}
	req.Close = true
	if len(token) > 0 {
		req.SetBasicAuth(hostname, token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, ErrFallback
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	return resp, nil
}

// FindEntry calls the remote backend to find matching keys and writes them to w.
func (remote *RemoteACL) FindEntry(w io.Writer, username, fingerprint string) error {
	fingerprint = splitKey(fingerprint)
	url := strings.Join([]string{remote.URL, constants.PerKeyPath, fingerprint, remote.Hostname, username}, "/")
	resp, err := getURL(httpclient(0), url, remote.Hostname, remote.Token)
	if err != nil {
		return err
	}
	return remote.parseResponse(w, resp.Body, username, fingerprint, false)
}

// Fetch calls the remote backend to find keys for the host and writes them to w.
func (remote *RemoteACL) Fetch(w io.Writer) error {
	url := strings.Join([]string{remote.URL, constants.PerHostPath, remote.Hostname}, "/")
	resp, err := getURL(httpclient(0), url, remote.Hostname, remote.Token)
	if err != nil {
		return err
	}
	return remote.parseResponse(w, resp.Body, "", "", true)
}

func splitLine(line []byte) (sig, msg []byte) {
	p := bytes.IndexByte(line, fieldDelim)
	if p < 1 {
		return nil, nil
	}
	return line[:p], line[p+1:]
}

func (remote *RemoteACL) verifyLine(sig, msg []byte) bool {
	out := make([]byte, delegatesign.DelegatedSignatureLength)
	if _, err := base64.StdEncoding.Decode(out, sig); err != nil {
		return false
	}
	_, ok := (delegatesign.DelegatedSignature)(out).Verify(remote.PublicKey, msg)
	return ok
}

func (remote *RemoteACL) parseResponse(w io.Writer, r io.Reader, user, fingerprint string, dontMatch bool) error {
	var found bool
	buf := bufio.NewReader(r)
	for {
		line, err := buf.ReadBytes(lineDelim)
		if len(line) > 0 {
			sig, msg := splitLine(line)
			if sig == nil || len(sig) == 0 || msg == nil || len(msg) == 0 {
				continue
			}
			if !remote.verifyLine(sig, msg) {
				continue
			}
			if !dontMatch {
				if e, ok := matchLine(msg, remote.Hostname, user, fingerprint); !ok {
					continue
				} else {
					found = true
					_, _ = fmt.Fprintln(w, e.AuthorizedKey)
				}
			} else {
				found = true
				_, _ = w.Write(msg)
				// _, _ = w.Write([]byte("\n"))
			}
		}
		if err == io.EOF {
			if found {
				return nil
			}
			return ErrNotFound
		}
		if err != nil {
			return err
		}
	}
}
