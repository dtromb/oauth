package oauth

import (
	"github.com/dtromb/oauth/hmac"
	"crypto/sha1"
	"encoding/base64"
	"math/rand"
	"time"
	"sort"
	"io"
	"strings"
	"strconv"
	"errors"
	"fmt"
	"net/url"
	"net/http"
)

type SignatureMethod uint8
const(
	HMACSHA1			SignatureMethod = iota
	RSASHA1
	PLAINTEXT
)

func (sm SignatureMethod) String() string {
	switch(sm) {
		case HMACSHA1: return "HMAC-SHA1"
		case RSASHA1: return "RSA-SHA1"
		case PLAINTEXT: return "PLAINTEXT"
	}
	panic("invalid signature method")
}

type Endpoint struct {
	requestTokenUrl url.URL			// initiate
	userAuthorizationUrl url.URL		// authorize
	accessTokenUrl url.URL			// token
}

type ConsumerKey interface {
	Key() []byte
}

type Token interface {
	ConsumerKey
	IsToken() bool
}

type consumerKey struct {
	key []byte
}

type tokenPair struct {
	consumerPrivateKey
}

func (ck *consumerKey) Key() []byte {
	res := make([]byte, len(ck.key))
	copy(res, ck.key)
	return res
}

func (t *tokenPair) IsToken() bool { return true }

type ConsumerPrivateKey interface {
	ConsumerKey
	Secret() []byte
}

type consumerPrivateKey struct {
	consumerKey
	secret []byte
}

func NewConsumerPrivateKey(key string, secret string) ConsumerPrivateKey {
	return &consumerPrivateKey{
		consumerKey: consumerKey{key: []byte(key)},
		secret: []byte(secret),
	}
}

func NewToken(key string, secret string) Token {
	return &tokenPair{
		consumerPrivateKey: consumerPrivateKey{
			consumerKey: consumerKey{key: []byte(key)},
			secret: []byte(secret),
		},
	}
}

func TokenFromTokenRequestResponse(r *http.Response) (Token,error) {
	body := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	read := 0
	for {
		br, err := r.Body.Read(buf[0:r.ContentLength])
		read += br
		body = append(body,buf[0:br]...)
		if read >= len(buf) {
			return nil, errors.New("token response too long")
		}
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
	}
	respString := string(body)
	//fmt.Println(respString)
	params, err := url.ParseQuery(respString)
	if err != nil {
		return nil, err
	}
	tokenKey := params.Get("oauth_token")
	tokenSecret := params.Get("oauth_token_secret")
	if tokenKey == "" || tokenSecret == "" {
		return nil, errors.New("token not present in response")
	}
	return NewToken(tokenKey, tokenSecret), nil
}

func (cpk *consumerPrivateKey) Secret() [] byte {
	res := make([]byte, len(cpk.secret))
	copy(res, cpk.secret)
	return res
}

type Request struct {
	*http.Request
	oauthKey ConsumerPrivateKey
	params url.Values
	bodyReader io.ReadCloser
	timestamp int64
	nonce []byte
	token Token
	signature []byte
	signatureMethod SignatureMethod
}

type OAuthClient struct {
	*http.Client
}

type RequestParameter struct {
	name string
	value string
}

var DefaultClient *OAuthClient = &OAuthClient{Client:http.DefaultClient}

func (rp *RequestParameter) String() string {
	var buf []byte
	buf = append(buf, encodeBytes([]byte(rp.name))...)
	buf = append(buf, '=')
	buf = append(buf, encodeBytes([]byte(rp.value))...)
	return string(buf)
}

type requestBodyReader struct {
	request *Request
	bodyForm []byte
	initialized bool
	readPos int
}

func NewRequest(method string, requrl string, oauthKey ConsumerPrivateKey) (*Request, error) {
	req := &Request{oauthKey: oauthKey, params: url.Values(make(map[string][]string))}
	req.bodyReader = &requestBodyReader{request:req}
	hreq, err := http.NewRequest(method, requrl, req.bodyReader)
	if err != nil {
		return nil, err
	}
	req.Request = hreq
	for k, m := range req.URL.Query() {
		for _, v := range m {
			req.params.Add(k,v)
		}
	}
	req.signatureMethod = HMACSHA1
	return req, nil
}

func (r *Request) SetSignatureMethod(useSm SignatureMethod) {
	r.signatureMethod = useSm
}

func (r *Request) SetTimestamp(useTs int64) {
	r.timestamp = useTs
}

func (r *Request) SetNonce(useNonce []byte) {
	r.nonce = useNonce
}

func (r *Request) SetToken(useToken Token) {
	r.token = useToken
}

func (r *Request) Key() ConsumerKey {
	key := &consumerKey{
		key: make([]byte, len(r.oauthKey.Key())),
	}
	copy(key.key, r.oauthKey.Key())
	return key
}

func (r *Request) AddParam(k, v string) {
	r.params.Add(k,v)
}

func (t *Request) createNonce() string {
	ts := time.Now().UnixNano()
	n := rand.Int31()
	nmat := ts << 32 | int64(n)
	vbt := strconv.Itoa(int(nmat))
	return base64.StdEncoding.EncodeToString([]byte(vbt))
}

func (r *Request) prepareSignature() (*url.URL,error) {
	if r.Method == "" {
		r.Method = "GET"
	}	
	
	// If we are a GET request, we need to adjust the URL to include any query parameters 
	// that are not currently in the URL.   For every other type of request, the additional
	// parameters will get placed in the request body be the request body reader.
	if r.Method == "GET" {
		err := r.rectifyGetQueryParams()
		if err != nil {
			return nil, err
		}
	}
	
	url := r.URL
	if url == nil {
		return nil, errors.New("no URL set before Sign() called")
	}
	scheme := string(encodeBytes([]byte(strings.ToLower(url.Scheme))))
	//fmt.Println("host: "+url.Host)
	host, port, defaultPort, err := splitHostParts(string(encodeBytes([]byte(strings.ToLower(url.Host)))),scheme)
	//fmt.Println("cooked host: "+host)
	if err != nil {
		return nil, err
	}
	if !defaultPort {
		host = host + ":" + strconv.Itoa(port)
	}
	urlString := scheme+"://"+host+"/"+url.Path
	url, err = url.Parse(urlString)
	if err != nil {
		return nil, err
	}
	r.params.Set("oauth_consumer_key",string(encodeBytes(r.oauthKey.Key())))
	if r.timestamp == 0 {
		r.timestamp = time.Now().Unix()
	}
	if r.nonce == nil {
		r.nonce = []byte(r.createNonce())
	}
	r.params.Set("oauth_signature_method",encodeString(r.signatureMethod.String()))
	r.params.Set("oauth_timestamp",strconv.Itoa(int(r.timestamp)))
	r.params.Set("oauth_nonce",string(r.nonce))
	if r.token != nil {
		//fmt.Println("SETTING TOKEN PARAM")
		r.params.Set("oauth_token",encodeString(string(r.token.Key())))
	}
	//r.params.Set("oauth_version","1.0")
	return url, nil
}

func (r *Request) constructBaseString() ([]byte, error) {
	url, err := r.prepareSignature()
	if err != nil {
		return nil, err
	}
	var baseString []byte
	params := sortRequestParameters(r.params)
	baseString = append(baseString, encodeBytes([]byte(strings.ToUpper(r.Method)))...)
	baseString = append(baseString, '&')
	baseString = append(baseString, encodeBytes([]byte(url.String()))...)
	baseString = append(baseString, '&')
	var paramString []byte
	for i, p := range params {
		paramString = append(paramString, []byte(p.String())...)
		if i < len(params)-1 {
			paramString = append(paramString, '&')
		}
		//fmt.Println(p.name+": "+p.value)
	}
	baseString = append(baseString, encodeBytes(paramString)...)
	return baseString, nil
}

func (r *Request) Sign() error {
	baseString, err := r.constructBaseString()
	if err != nil {
		return err
	}
	switch(r.signatureMethod) {
		case HMACSHA1: {
			var keyMaterial []byte
			keyMaterial = append(keyMaterial, encodeBytes(r.oauthKey.Secret())...)
			keyMaterial = append(keyMaterial, '&')
			if tok, ok := r.token.(*tokenPair); ok {
				keyMaterial = append(keyMaterial, encodeBytes(tok.consumerPrivateKey.Secret())...)
			}
			signatureBytes := hmac.Hmac(sha1.New(), keyMaterial, baseString)
			r.signature = make([]byte,base64.StdEncoding.EncodedLen(len(signatureBytes)))
			base64.StdEncoding.Encode(r.signature, signatureBytes)
			//fmt.Println("SIGNATURE: "+string(r.signature))
		}
		case RSASHA1: {
			panic("RSA-SHA1 unimplemented")
		}
		case PLAINTEXT: {			
			var signatureBytes []byte
			signatureBytes = append(signatureBytes, encodeBytes(r.oauthKey.Secret())...)
			signatureBytes = append(signatureBytes, '&')
			if tok, ok := r.token.(*tokenPair); ok {
				signatureBytes = append(signatureBytes, encodeBytes(tok.consumerPrivateKey.Secret())...)
			}
			r.signature = signatureBytes
		}
	}
	// Set OAuth headers.
	
	var authHeader []byte
	setField := func(k, v string, last bool) {
		authHeader = append(authHeader, []byte(fmt.Sprintf("%s=\"%s\"",k,v))...)
		if !last {
			authHeader = append(authHeader, []byte(",")...)
		}
	}
	setField("oauth_consumer_key", string(r.oauthKey.Key()), false)
	if r.token != nil {
		setField("oauth_token", string(r.token.Key()), false)
	}
	setField("oauth_signature_method", r.signatureMethod.String(), false)
	setField("oauth_signature", string(encodeBytes(r.signature)), false)
	setField("oauth_timestamp", strconv.Itoa(int(r.timestamp)), false)
	setField("oauth_nonce", string(encodeBytes(r.nonce)), false)
	//setField("oauth_version", "1.0", true)
	r.Header.Set("Authorization", "OAuth "+string(authHeader))
	
	/*
	r.Header.Del("Authorization")	
	setField := func(k, v string) {
		r.Header.Add("Authorization", fmt.Sprintf("%s=\"%s\"", k, v))
	}
	setField("oauth_consumer_key", string(r.oauthKey.Key()))
	if r.token != nil {
		setField("oauth_token", string(r.token.Key()))
	}
	setField("oauth_signature_methods", r.signatureMethod.String())
	setField("oauth_signature", string(r.signature))
	setField("oauth_timestamp", strconv.Itoa(int(r.timestamp)))
	setField("oauth_nonce", string(r.nonce))
	setField("oauth_version", "1.0")
	*/
	return nil
}

// Rewrite the URL to include any new parameters added by the AddParam() 
// function between the request creation and execution.  Since the original
// query params have already been inserted into the /params/ field, we only need
// re-write the entire values set into a new query.
func (r *Request) rectifyGetQueryParams() error {
	newUrlText := r.URL.String()
	k := strings.Index(newUrlText,"?")
	if k > 0 {
		newUrlText = newUrlText[0:k] // truncate query
	}
	newUrlText = newUrlText+"?"+r.params.Encode()
	newUrl, err := url.Parse(newUrlText)
	if err != nil {
		return err
	}
	r.URL = newUrl
	return nil
}

func (br *requestBodyReader) initialize() {
	bodyParams := url.Values(make(map[string][]string)) 
	urlParams := br.request.URL.Query()
	for k, rm := range br.request.params {
		if um, has := urlParams[k]; !has {
			// The url contains none of the request params; add them all to the body.
			bodyParams[k] = rm
		} else {
			// Index all of the url param values for this key.
			idx := make(map[string]bool)
			for _, p := range um {
				idx[p] = true
			}
			// Go through the request params and add each not in the index to the body.
			for _, p := range rm {
				if _, has := idx[p]; !has {
					if bm, has := bodyParams[p]; has {
						bodyParams[p] = append(bm, p)
					} else {
						bodyParams[p] = []string{p}
					}
				}
			}
		}
	}
	if len(bodyParams) > 0 {
		// Urlencode all of the body parameters.
		br.bodyForm = []byte(bodyParams.Encode())
	} 
	br.initialized = true
}

func (br *requestBodyReader) Read(p []byte) (n int, err error) {
	if br.request.Method != "POST" {
		return 0, io.EOF
	}
	if !br.initialized {
		br.initialize()
	}
	if br.bodyForm == nil {
		//fmt.Println("BODY: EOF")
		return 0, io.EOF
	}
	rl := len(p)
	if len(br.bodyForm) - br.readPos < rl {
		rl = len(br.bodyForm) - br.readPos
	}
	if rl == 0 {
		return 0, io.EOF
	}
	copy(p, br.bodyForm[br.readPos:br.readPos+rl])
	br.readPos += rl
	//fmt.Println("BODY: >"+string(p[0:rl]))
	return rl, nil
}

func (br *requestBodyReader) Close() error {
	br.initialized = false
	br.bodyForm = nil
	return nil
}

///

func isUnreservedCharacter(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
	       (b >= 'A' && b <= 'Z') ||
		   (b >= '0' && b <= '9') ||
		   (b == '-' || b == '.' || b =='_' || b == '~')
}

func encodeString(str string) string {
	return string(encodeBytes([]byte(str)))
}

func encodeBytes(in []byte) []byte {
	out := make([]byte, 0, len(in))
	for _, b := range in {
		if isUnreservedCharacter(b) {
			out = append(out, b)
		} else {
			out = append(out, '%')
			out = append(out, []byte(fmt.Sprintf("%2.2X", b))...)
		}
	}
	return out
}

func hexdigit(b byte) (int,bool) {
	if b >= '0' && b <= '9' {
		return int(b-'0'), true
	}
	if b >= 'a' && b <= 'f' {
		return int(b-'a'+10), true
	}
	if b >= 'A' && b <= 'F' {
		return int(b-'A'+10), true
	}
	return 0, false
}

func decodeString(str string) (string,error) {
	res, err := decodeBytes([]byte(str))
	if err != nil {
		return "", err
	}
	return string(res), err
}

func decodeBytes(in []byte) ([]byte,error) {
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		b := in[i] 
		if b == '%' {
			if i > len(in)-3 {
				return nil, errors.New("unexpected end of input after %-escape")
			}
			k, ok := hexdigit(in[i+1])
			if !ok {
				return nil, errors.New("invalid hex digit in input")
			}
			cc := k << 8
			k, ok = hexdigit(in[i+2])
			if !ok {
				return nil, errors.New("invalid hex digit in input")
			}
			cc = cc | k
			out = append(out, byte(cc))
		} else {
			if isUnreservedCharacter(b) {
				out = append(out, b)
			} else {
				return nil, errors.New("invalid reserved character in input")
			}
		}
	}
	return out, nil
}

func defaultSchemePort(scheme string) (int, bool) {
	switch(strings.ToLower(scheme)) {
		case "http": return 80, true
		case "https": return 443, true
	}
	return 0, false
}

func splitHostParts(hostString string, scheme string) (host string, port int, defaultPort bool, e error) {
	k := strings.Index(hostString, ":")
	dport, _ := defaultSchemePort(scheme)
	if k < 0 {
		return hostString, dport, true, nil
	}
	port, err := strconv.Atoi(hostString[k+1:])
	if err != nil {
		return "", 0, false, err
	}
	return hostString[0:k], port, dport == port, nil
}

type sortedRequestParams []*RequestParameter
func (srp sortedRequestParams) Len() int { return len(srp) }
func (srp sortedRequestParams) Swap(i, j int) { srp[i], srp[j] = srp[j], srp[i] }
func (srp sortedRequestParams) Less(i, j int) bool { 
	if encodeString(srp[i].name) < encodeString(srp[j].name) { return true }
	if encodeString(srp[i].name) > encodeString(srp[j].name) { return false }
	if encodeString(srp[i].value) < encodeString(srp[j].value) { return true }
	return false
}

func sortRequestParameters(p url.Values) []*RequestParameter {
	var srp sortedRequestParams
	for k, m := range p {
		for _, v := range m {
			srp = append(srp, &RequestParameter{k,v})
		}
	}
	sort.Sort(srp)
	return []*RequestParameter(srp)
}


func (c *OAuthClient) Do(req *Request) (*http.Response, error) {
	err := req.Sign()
	if err != nil {
		return nil, err
	}
	return c.Client.Do(req.Request)
}

// The rest of the http.Client methods are forbidden - they are not authorization-aware
// and so there is no way to associate an auth state with the generated request.
//
// We provide alternatives as noted.
func (c *OAuthClient) Get(url string) (resp *http.Response, err error) {
	panic("OAuthClient.Get() is not usable; use OAuthClient.OAuthGet() instead")
}

func (c *OAuthClient) Head(url string) (resp *http.Response, err error) {
	panic("OAuthClient.Head() is not usable; use OAuthClient.OAuthHead() instead")
}

func (c *OAuthClient) Post(url string, bodyType string, body io.Reader) (resp *http.Response, err error) {
	panic("OAuthClient.Post() is not usable; use OAuthClient.OAuthPost() instead")
}

func (c *OAuthClient) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	panic("OAuthClient.PostForm() is not usable; use OAuthClient.OAuthPostForm() instead")
}