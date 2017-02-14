

### OAuth 1.0 support for Go via \*http.Request

```go 

	// Test case from RFC5849, section 3.4.1.1  (as corrected by Errata #2550)
	expectedSignature := `r6/TJjbCOr97/+UU0NsvSne7s5g=`
	testCpk := NewConsumerPrivateKey("9djdj82h48djs9d2","j49sk3j29djd")	
	req, err := NewRequest("POST","http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", testCpk)
	...
	req.SetTimestamp(137131201)
	req.SetNonce([]byte("7d8f3e4a"))
	req.SetToken(NewToken("kkk9d7dh3k39sjv7","dh893hdasih9"))
	req.SetSignatureMethod(HMACSHA1)
	req.AddParam("c2","")
	req.AddParam("a3","2 q")
	...
	err = req.Sign()
	
	// Request will now be sent with OAuth signature.
```