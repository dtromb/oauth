package hmac


import (
	"encoding/base64"
	"fmt"
	"testing"
	"crypto/sha1"
)

func TestRfc2104(t *testing.T) {
	key := []byte(`kd94hf93k423kf44&pfkkdhi9sl3r4s00`)
	text := []byte(`GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal`)
	mac := Hmac(sha1.New(), key, text)
	fmt.Println(base64.StdEncoding.EncodeToString(mac))
}