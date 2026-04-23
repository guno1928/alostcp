package core

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

func handshakeFrame(conn *net.TCPConn, password string, plaintext []byte) error {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return err
	}
	cipherLen := 16 + len(plaintext)
	frame := make([]byte, 4+cipherLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(cipherLen))
	copy(frame[4:20], nonce)

	stream := newHandshakeCipher(password, nonce)
	stream.XORKeyStream(frame[20:], plaintext)

	_, err := conn.Write(frame)
	return err
}

func readHandshakeFrame(conn *net.TCPConn, password string) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	cipherLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if cipherLen < 16 {
		return nil, errors.New("alostcp: invalid handshake frame")
	}
	cipherBuf := make([]byte, cipherLen)
	if _, err := io.ReadFull(conn, cipherBuf); err != nil {
		return nil, err
	}
	nonce := cipherBuf[:16]
	enc := cipherBuf[16:]
	plain := make([]byte, len(enc))

	stream := newHandshakeCipher(password, nonce)
	stream.XORKeyStream(plain, enc)

	return plain, nil
}

var handshakeOK = []byte("OK")
var handshakeFail = []byte("FAIL")

func deriveIVs(password string, otp []byte) (ivA, ivB [16]byte) {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write(otp)
	h.Write([]byte{0})
	copy(ivA[:], h.Sum(nil))

	h.Reset()
	h.Write([]byte(password))
	h.Write(otp)
	h.Write([]byte{1})
	copy(ivB[:], h.Sum(nil))
	return
}

func serverHandshake(conn *net.TCPConn, password string) ([]byte, error) {
	otp := make([]byte, 16)
	if _, err := io.ReadFull(randReader, otp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("alostcp: failed to generate OTP: %w", err)
	}
	if err := handshakeFrame(conn, password, otp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("alostcp: handshake send failed: %w", err)
	}

	response, err := readHandshakeFrame(conn, password)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("alostcp: handshake recv failed: %w", err)
	}

	expected := sha256.Sum256(append(otp, []byte(password)...))
	if subtle.ConstantTimeCompare(response, expected[:]) != 1 {
		_ = handshakeFrame(conn, password, handshakeFail)
		conn.Close()
		return nil, errors.New("alostcp: handshake failed: invalid password or MITM detected")
	}

	if err := handshakeFrame(conn, password, handshakeOK); err != nil {
		conn.Close()
		return nil, fmt.Errorf("alostcp: handshake confirm failed: %w", err)
	}

	return otp, nil
}

func clientHandshake(conn *net.TCPConn, password string) ([]byte, error) {
	otp, err := readHandshakeFrame(conn, password)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("alostcp: handshake recv failed: %w", err)
	}

	response := sha256.Sum256(append(otp, []byte(password)...))
	if err := handshakeFrame(conn, password, response[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("alostcp: handshake send failed: %w", err)
	}

	confirm, err := readHandshakeFrame(conn, password)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("alostcp: handshake confirm recv failed: %w", err)
	}
	if string(confirm) != "OK" {
		conn.Close()
		return nil, errors.New("alostcp: handshake rejected by server")
	}

	return otp, nil
}
