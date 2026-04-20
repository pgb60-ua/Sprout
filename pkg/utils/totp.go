package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	TOTPPeriod = 30 * time.Second
	TOTPDigits = 6
	SecretLen  = 20
)

func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, SecretLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("no se pudo generar el secreto TOTP: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func GenerateTOTPCode(secret string, now time.Time) (string, error) {
	// Decodifico el secreto a bytes
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("secreto TOTP no valido %w", err)
	}

	// Calculo el contador, cuantos periodos de 30s han pasado desde 1970
	counter := uint64(now.Unix() / int64(TOTPPeriod/time.Second))
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	// Calculo HMAC-SHA1 de contador con el secreto como clave
	mac := hmac.New(sha1.New, key) // Creo un generador HMAC diciendole que use sha1 y el secreto como clave
	mac.Write(msg[:])              // Los [:] es para convertir a slice
	sum := mac.Sum(nil)            //Genero el hash (da 20 bytes)

	offset := sum[len(sum)-1] & 0x0f // Esto hace que se coja el ultimo byte y el 0x0f que se cojan los 4 bits mas bajos, lo que da un numero entre 0 y 15 de offset
	// Ahora leemos 4 bytes desde el offset y los une en un solo numero de 32 bits con <<, el | es un OR
	code := (int(sum[offset])&0x7f)<<24 | // Usamos 0x7f para poner el bit mas significativo a 0 y que nunca sea negativo
		(int(sum[offset+1])&0xff)<<16 | // Usamos 0xff para castear a int asegurandonos de que solo se usan los 8 bits mas bajos del byte
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)

	// Obtengo en cuantos numeros se truncara
	mod := 1
	for range TOTPDigits {
		mod *= 10
	}

	// Acorto el numero
	value := code % mod

	// %0*d para rellenar con 0 en vez de espacio y para indicarle que longitud es la cadena en un parametro (*)
	return fmt.Sprintf("%0*d", TOTPDigits, value), nil
}

func VerifyTOTPCode(secret, code string, now time.Time) bool {
	// Elimino espacios y saltos de linea al principio y final, por si el usuario lo introduce
	code = strings.TrimSpace(code)

	// Genero el codigo anterior, el codigo actual y el codigo siguiente para darle margen al usuario y si uno de los 3 casa return true
	for _, delta := range []time.Duration{-TOTPPeriod, 0, TOTPPeriod} {
		expected, err := GenerateTOTPCode(secret, now.Add(delta))
		if err == nil && expected == code {
			return true
		}
	}

	return false
}

func BuildOTPAuthURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(TOTPDigits))
	q.Set("period", strconv.Itoa(int(TOTPPeriod/time.Second)))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
