package uncheckedgcm

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	key             = []byte{75, 128, 231, 130, 27, 239, 223, 21, 202, 96, 107, 195, 101, 128, 104, 143}
	nonce           = []byte{78, 81, 149, 178, 11, 68, 48, 35, 9, 70, 221, 214, 115, 12, 131, 250}
	tag             = [16]byte{244, 140, 85, 134, 140, 233, 4, 61, 242, 195, 243, 243, 5, 171, 66, 137}
	decryptedPacket = []byte{13, 240, 125, 2, 0, 0, 0, 0, 7, 27, 120, 2, 96, 0, 164, 33, 60, 236, 147, 76}
	encryptedPacket = []byte{198, 81, 89, 132, 220, 248, 192, 190, 44, 32, 138, 67, 10, 145, 197, 1, 99, 129, 251, 155}
)

func TestEncryptChunks(t *testing.T) {
	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	gcm := newGCMEncrypter(block, nonce, nil)

	ciphertext := gcm.Encrypt(nil, []byte{13, 240, 125, 2})
	assert.Nil(t, err)
	assert.Equal(t, encryptedPacket[:4], ciphertext)

	ciphertext = gcm.Encrypt(nil, decryptedPacket[4:20])
	assert.Nil(t, err)
	assert.Equal(t, encryptedPacket[4:20], ciphertext)
}

func TestEncryptTag(t *testing.T) {
	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	gcm := newGCMEncrypter(block, nonce, nil)

	ciphertext := []byte{0, 0, 0, 0}
	ciphertext = gcm.Encrypt(ciphertext[:0], ciphertext)
	assert.Nil(t, err)

	assert.Equal(t, tag, gcm.Tag())
}

func TestDecryptChunks(t *testing.T) {
	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	gcm := newGCMDecrypter(block, nonce, nil)

	plaintext, err := gcm.Decrypt(nil, encryptedPacket[:4])
	assert.Nil(t, err)
	assert.Equal(t, []byte{13, 240, 125, 2}, plaintext)

	plaintext, err = gcm.Decrypt(nil, encryptedPacket[4:20])
	assert.Nil(t, err)
	assert.Equal(t, decryptedPacket[4:20], plaintext)
}

func TestDecryptTag(t *testing.T) {
	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	gcm := newGCMDecrypter(block, nonce, nil)

	ciphertext := []byte{0, 0, 0, 0}
	_, err = gcm.Decrypt(ciphertext[:0], ciphertext)
	assert.Nil(t, err)

	assert.Equal(t, tag, gcm.Tag())
}

func TestDecryptVerifyTag(t *testing.T) {
	block, err := aes.NewCipher(key)
	assert.Nil(t, err)

	gcm := newGCMDecrypter(block, nonce, nil)

	ciphertext := []byte{0, 0, 0, 0}
	_, err = gcm.Decrypt(ciphertext[:0], ciphertext)
	assert.Nil(t, err)

	err = gcm.Verify(tag[:])
	assert.Nil(t, err)
}
