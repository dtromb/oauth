package hmac

import (
	"hash"
	
)

// HMAC message authentication codes as defined by RFC2104

 func Hmac(hf hash.Hash, key, message []byte) []byte {
	hf.Reset()
    if (len(key) > hf.BlockSize()) {
		hf.Write(key)
        key = hf.Sum(nil) // keys longer than blocksize are shortened
    		hf.Reset()
	}
    for (len(key) < hf.BlockSize()) {
		key = append(key, 0)
    }
   
	opad := make([]byte, hf.BlockSize())
	ipad := make([]byte, hf.BlockSize())
	for i := 0; i < hf.BlockSize(); i++ {
		opad[i] = 0x5c ^ key[i]
		ipad[i] = 0x36 ^ key[i]
	}
	hf.Write(ipad)
	hf.Write(message)
	b := hf.Sum(nil)
	hf.Reset()
	hf.Write(opad)
	hf.Write(b)
	return hf.Sum(nil)
}