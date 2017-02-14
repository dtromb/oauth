package oauth


import (
	"net/url"
	"bytes"
	"errors"
	"net/http"
	"testing"
	"fmt"
)

func TestRequestSignatureBaseString(t *testing.T) {
	// Test case from RFC5849, section 3.4.1.1
	expectedBaseString := `POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q`+
     					  `%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_`+
     					  `key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m`+
     					  `ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk`+
     					  `9d7dh3k39sjv7`
	testCpk := NewConsumerPrivateKey("9djdj82h48djs9d2","kd94hf93k423kf44")	
	req, err := NewRequest("POST","http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", testCpk)
	if err != nil {
		t.Error(fmt.Sprintf("Error creating oauth request: %s\n", err.Error()))
		t.FailNow()
	}
	
	req.AddParam("c2","")
	req.AddParam("a3","2 q")
	
	req.SetTimestamp(137131201)
	req.SetNonce([]byte("7d8f3e4a"))
	req.SetToken(NewToken("kkk9d7dh3k39sjv7","dh893hdasih9"))
	
	baseString, err := req.constructBaseString()
	if err != nil {
		t.Error(fmt.Sprintf("Error construction base string: %s\n", err.Error()))
		t.FailNow()
	}
	if string(baseString) != expectedBaseString {
		t.Error(fmt.Sprintf("Base string encoding failed.  (expected:\n%s\ngot:\n%s\n)\n", expectedBaseString, string(baseString)))
		t.FailNow()
	}
}

func TestRsaSha1Signature(t *testing.T) {	
	// Test case from RFC5849, section 3.4.1.1  (as corrected by Errata #2550)
	expectedSignature := `r6/TJjbCOr97/+UU0NsvSne7s5g=`
	testCpk := NewConsumerPrivateKey("9djdj82h48djs9d2","j49sk3j29djd")	
	req, err := NewRequest("POST","http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", testCpk)
	if err != nil {
		t.Error(fmt.Sprintf("Error creating oauth request: %s\n", err.Error()))
		t.FailNow()
	}	
	req.SetTimestamp(137131201)
	req.SetNonce([]byte("7d8f3e4a"))
	req.SetToken(NewToken("kkk9d7dh3k39sjv7","dh893hdasih9"))
	req.SetSignatureMethod(HMACSHA1)
	req.AddParam("c2","")
	req.AddParam("a3","2 q")
	err = req.Sign()
	if err != nil {
		t.Error(fmt.Sprintf("Error signing request: %s\n", err.Error()))
		t.FailNow()
	}
	if string(req.signature) != expectedSignature {
		t.Error(fmt.Sprintf("computed signature is incorrect (\nexpected:\n%s\ngot:\n%s\n)\n", expectedSignature, string(req.signature)))
		t.FailNow()
	}
}

// This uses the test server provided at http://oauthbin.com.   If it's
// down, the test will not pass!

func TestOAuth(t *testing.T) {
	
	client := DefaultClient
	
	requestTokenUrl := 	`http://oauthbin.com/v1/request-token`
	accessTokenUrl :=  	`http://oauthbin.com/v1/access-token`
	resourceUrl := 		`http://oauthbin.com/v1/echo`
	
	cKey := NewConsumerPrivateKey("key", "secret")
	
	// First, attempt to get a request token.
	//fmt.Println(" ***** temp credential request")
	req, err := NewRequest("GET", requestTokenUrl, cKey)
	if err != nil {
		t.Error(err)
		return
	}
	//str, _ := req.constructBaseString()
	//fmt.Println(string(str))
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Error(errors.New("server returned error status"))
		return
	}
	// Extract the token from the successful token request.
	token, err := TokenFromTokenRequestResponse(resp)
	if err != nil {
		t.Error(err)
		return
	}
	
	//fmt.Println("ok\n ***** access token request")
	// Request an access credential with the request token.
	req, err = NewRequest("GET", accessTokenUrl, cKey)
	if err != nil {
		t.Error(err)
		return
	}
	req.SetToken(token)
	//str, _ = req.constructBaseString()
	//fmt.Println(string(str))
	resp, err = client.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Error(errors.New("server returned error status"))
		return
	}
	
	// Extract the access token from the successful token request.
	accessToken, err := TokenFromTokenRequestResponse(resp)
	if err != nil {
		t.Error(err)
		return
	}
	
	//fmt.Println("ok\n ***** resource request")
	// Finally, make an authenticated request to the echo service.
	req, err = NewRequest("GET", resourceUrl, cKey)
	if err != nil {
		t.Error(err)
		return
	}
	req.SetToken(accessToken)
	message := "Hello, world!"
	req.AddParam("greeting", message)
	//str, _ = req.constructBaseString()
	//fmt.Println(string(str))
	
	resp, err = client.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		return
	}
	
	// Collect the message body.
	buf := bytes.Buffer{}
	buf.ReadFrom(resp.Body)
	reply := buf.String()
	
	// Decode it, we should have the request echoed back.
	vals, err := url.ParseQuery(reply)
	if err != nil {
		t.Error(errors.New("malformed echo response"))
	}
	reply = vals.Get("greeting")
	if reply != message {
		t.Error(errors.New("echo response differed from greeting"))
	}
}