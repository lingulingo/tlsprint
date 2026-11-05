package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// Request is a fluent per-request builder, created with Client.R(). A Request
// is not safe for concurrent use.
type Request struct {
	client *Client

	ctx        context.Context
	headers    http.Header
	query      url.Values
	pathParams map[string]string
	body       any
	result     any
	_cancel    context.CancelFunc // set by SetTimeout
	baseURL    string             // snapshot of Client.baseURL at construction

	rawURL string
}

func newRequest(c *Client) *Request {
	// baseURL is snapshotted here (R holds c.mu) so a concurrent SetBaseURL
	// cannot change the prefix halfway through building a request.
	r := &Request{
		client:  c,
		baseURL: c.baseURL,
		headers: make(http.Header),
		query:   make(url.Values),
		ctx:     context.Background(),
	}
	for k, vs := range c.defaultHeaders {
		for _, v := range vs {
			r.headers.Add(k, v)
		}
	}
	return r
}

// ---- headers, auth ----

// SetHeader sets a request header.
func (r *Request) SetHeader(key, value string) *Request {
	r.headers.Set(key, value)
	return r
}

// SetHeaders sets several request headers.
func (r *Request) SetHeaders(headers map[string]string) *Request {
	for k, v := range headers {
		r.headers.Set(k, v)
	}
	return r
}

// SetBasicAuth sets the Authorization header from a user/password pair.
func (r *Request) SetBasicAuth(username, password string) *Request {
	tok := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	r.headers.Set("Authorization", "Basic "+tok)
	return r
}

// SetAuthToken sets a bearer token.
func (r *Request) SetAuthToken(token string) *Request {
	r.headers.Set("Authorization", "Bearer "+token)
	return r
}

// SetCookie adds a cookie. Repeated calls accumulate into one Cookie header
// ("a=1; b=2") instead of emitting several headers, because servers and
// proxies only read the first Cookie header of a request.
func (r *Request) SetCookie(name, value string) *Request {
	kv := name + "=" + value
	if prior := r.headers.Get("Cookie"); prior != "" {
		r.headers.Set("Cookie", prior+"; "+kv)
		return r
	}
	r.headers.Set("Cookie", kv)
	return r
}

// ---- query & path params ----

// SetQueryParam appends a query parameter.
func (r *Request) SetQueryParam(key, value string) *Request {
	r.query.Set(key, value)
	return r
}

// SetQueryParams appends several query parameters.
func (r *Request) SetQueryParams(params map[string]string) *Request {
	for k, v := range params {
		r.query.Set(k, v)
	}
	return r
}

// SetPathParam substitutes {name} or :name placeholders in the URL path.
func (r *Request) SetPathParam(key, value string) *Request {
	if r.pathParams == nil {
		r.pathParams = make(map[string]string)
	}
	r.pathParams[key] = value
	return r
}

// SetPathParams substitutes several path placeholders.
func (r *Request) SetPathParams(params map[string]string) *Request {
	for k, v := range params {
		r.SetPathParam(k, v)
	}
	return r
}

// ---- body helpers ----

// SetBody sets the request body. []byte and string are sent verbatim;
// url.Values / map[string]string are form-encoded; anything else is JSON
// encoded (Content-Type defaults are applied only when not already set).
func (r *Request) SetBody(body any) *Request {
	r.body = body
	return r
}

// SetFormData is shorthand for a url.Values body.
func (r *Request) SetFormData(data map[string]string) *Request {
	v := make(url.Values, len(data))
	for k, val := range data {
		v.Set(k, val)
	}
	r.body = v
	return r
}

// SetMultipartFormData sends the values as multipart/form-data.
func (r *Request) SetMultipartFormData(data map[string]string) *Request {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range data {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name="%s"`, escapeQuotes(k)))
		fw, err := mw.CreatePart(h)
		if err != nil {
			continue
		}
		_, _ = fw.Write([]byte(v))
	}
	_ = mw.Close()
	r.headers.Set("Content-Type", mw.FormDataContentType())
	r.body = buf.Bytes()
	return r
}

// SetResult registers a pointer that is JSON-decoded from the response body
// when the status is 2xx.
func (r *Request) SetResult(v any) *Request {
	r.result = v
	return r
}

// SetContext sets the request context.
func (r *Request) SetContext(ctx context.Context) *Request {
	r.ctx = ctx
	return r
}

// SetTimeout overrides the client timeout for this request.
func (r *Request) SetTimeout(d time.Duration) *Request {
	ctx, cancel := context.WithTimeout(r.ctx, d)
	r.ctx = ctx
	r._cancel = cancel
	return r
}

// ---- verbs ----
//
// Every verb accepts optional trailing header maps:
//
//	c.R().Get("https://…", map[string]string{"X-Key": "v1"})
//	c.R().Post("https://…", map[string]string{"X-Key": "v2"})
//
// which is equivalent to chaining SetHeaders before the verb.

// Get performs a GET request. headers is an optional map of request headers.
func (r *Request) Get(rawURL string, headers ...map[string]string) (*Response, error) {
	return r.Execute(http.MethodGet, rawURL, headers...)
}

// Post performs a POST request. headers is an optional map of request headers.
func (r *Request) Post(rawURL string, headers ...map[string]string) (*Response, error) {
	return r.Execute(http.MethodPost, rawURL, headers...)
}

// Put performs a PUT request. headers is an optional map of request headers.
func (r *Request) Put(rawURL string, headers ...map[string]string) (*Response, error) {
	return r.Execute(http.MethodPut, rawURL, headers...)
}

// Patch performs a PATCH request. headers is an optional map of request headers.
func (r *Request) Patch(rawURL string, headers ...map[string]string) (*Response, error) {
	return r.Execute(http.MethodPatch, rawURL, headers...)
}

// Delete performs a DELETE request. headers is an optional map of request headers.
func (r *Request) Delete(rawURL string, headers ...map[string]string) (*Response, error) {
	return r.Execute(http.MethodDelete, rawURL, headers...)
}

// Head performs a HEAD request. headers is an optional map of request headers.
func (r *Request) Head(rawURL string, headers ...map[string]string) (*Response, error) {
	return r.Execute(http.MethodHead, rawURL, headers...)
}

// Options performs an OPTIONS request. headers is an optional map of request
// headers.
func (r *Request) Options(rawURL string, headers ...map[string]string) (*Response, error) {
	return r.Execute(http.MethodOptions, rawURL, headers...)
}

// Execute builds and runs the request. headers is an optional map of request
// headers.
func (r *Request) Execute(method, rawURL string, headers ...map[string]string) (*Response, error) {
	if r._cancel != nil {
		defer r._cancel()
	}
	for _, h := range headers {
		for k, v := range h {
			r.headers.Set(k, v)
		}
	}
	finalURL, err := r.resolveURL(rawURL)
	if err != nil {
		return nil, err
	}

	body, contentType, err := r.encodeBody()
	if err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(r.ctx, method, finalURL, reader)
	if err != nil {
		return nil, err
	}
	for k, vs := range r.headers {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	if contentType != "" && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", contentType)
	}

	start := time.Now()
	resp, err := r.client.do(httpReq)
	dur := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	out := &Response{
		statusCode: resp.StatusCode,
		status:     resp.Status,
		header:     resp.Header.Clone(),
		proto:      resp.Proto,
		requestURL: resp.Request.URL.String(),
		duration:   dur,
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, fmt.Errorf("client: read response body: %w", err)
	}
	out.rawBody = raw
	out.body = decodeBody(resp.Header.Get("Content-Encoding"), raw)

	// Decode into the result target on 2xx. Decode the *decompressed* body:
	// presets send Accept-Encoding themselves, which suppresses net/http's
	// transparent decompression, so raw holds compressed wire bytes.
	if r.result != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(out.body, r.result); err != nil {
			return out, fmt.Errorf("client: decode response into result: %w", err)
		}
	}
	return out, nil
}

func (r *Request) resolveURL(rawURL string) (string, error) {
	u := rawURL
	if r.baseURL != "" && !strings.Contains(u, "://") {
		base := strings.TrimSuffix(r.baseURL, "/")
		u = base + "/" + strings.TrimPrefix(u, "/")
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("client: parse url: %w", err)
	}
	for k, v := range r.pathParams {
		parsed.Path = strings.ReplaceAll(parsed.Path, "{"+k+"}", v)
		parsed.Path = strings.ReplaceAll(parsed.Path, ":"+k, v)
		parsed.RawPath = strings.ReplaceAll(parsed.RawPath, "{"+k+"}", url.PathEscape(v))
	}
	if len(r.query) > 0 {
		q := parsed.Query()
		for k, vs := range r.query {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		parsed.RawQuery = q.Encode()
	}
	return parsed.String(), nil
}

func (r *Request) encodeBody() (body []byte, contentType string, err error) {
	switch b := r.body.(type) {
	case nil:
		return nil, "", nil
	case []byte:
		return b, "", nil
	case string:
		return []byte(b), "", nil
	case io.Reader:
		data, err := io.ReadAll(b)
		if err != nil {
			return nil, "", err
		}
		return data, "", nil
	case url.Values:
		return []byte(b.Encode()), "application/x-www-form-urlencoded", nil
	case map[string]string:
		v := make(url.Values, len(b))
		for k, val := range b {
			v.Set(k, val)
		}
		return []byte(v.Encode()), "application/x-www-form-urlencoded", nil
	default:
		data, err := json.Marshal(b)
		if err != nil {
			return nil, "", fmt.Errorf("client: encode json body: %w", err)
		}
		return data, "application/json", nil
	}
}

func escapeQuotes(s string) string {
	return strings.NewReplacer("\\", "\\\\", `"`, "\\\"").Replace(s)
}
