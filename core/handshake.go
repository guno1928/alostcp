package core

import (
	"context"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/gtank/ristretto255"
)

const (
	protocolMagic         = "ALTC"
	protocolVersion       = 3
	recvLimitFieldSize    = 4
	helloPrefixSize       = len(protocolMagic) + 1 + recvLimitFieldSize
	clientSIDOffset       = helloPrefixSize
	clientPointOffset     = clientSIDOffset + cpaceSIDSize
	clientHelloSize       = clientPointOffset + cpacePointSize
	serverPointOffset     = helloPrefixSize
	serverHelloSize       = serverPointOffset + cpacePointSize
	finishedSize          = 32
	sessionKeySize        = 16
	passwordKeySize       = 32
	passwordKDFIterations = 600_000
	maxCachedPasswordKeys = 64
)

const (
	labelPasswordSalt   = "alostcp v3 password"
	labelChannelClient  = "alostcp v3 client"
	labelChannelServer  = "alostcp v3 server"
	labelTranscript     = "alostcp v3 transcript"
	labelClientFinished = "alostcp v3 client finished"
	labelServerFinished = "alostcp v3 server finished"
	labelClientToServer = "alostcp v3 client to server"
	labelServerToClient = "alostcp v3 server to client"
)

var cpaceChannelID = lvCat([]byte(labelChannelClient), []byte(labelChannelServer))

var (
	ErrHandshake      = errors.New("alostcp: handshake failed")
	ErrEmptyPassword  = errors.New("alostcp: password must not be empty")
	ErrUnsupportedCPU = errors.New("alostcp: CPU lacks hardware AES support")

	errBadHello    = fmt.Errorf("%w: unexpected protocol hello", ErrHandshake)
	errBadFinished = fmt.Errorf("%w: peer failed the password proof", ErrHandshake)
)

type passwordKey [passwordKeySize]byte

type passwordFingerprint [sha256.Size]byte

var passwordKeyCache = struct {
	sync.Mutex
	keys map[passwordFingerprint]passwordKey
}{keys: make(map[passwordFingerprint]passwordKey)}

func cachedPasswordKey(fingerprint *passwordFingerprint) (passwordKey, bool) {
	passwordKeyCache.Lock()
	defer passwordKeyCache.Unlock()
	key, ok := passwordKeyCache.keys[*fingerprint]
	return key, ok
}

func storePasswordKey(fingerprint *passwordFingerprint, key passwordKey) {
	passwordKeyCache.Lock()
	defer passwordKeyCache.Unlock()
	if len(passwordKeyCache.keys) >= maxCachedPasswordKeys {
		clear(passwordKeyCache.keys)
	}
	passwordKeyCache.keys[*fingerprint] = key
}

func stretchPassword(password string) (passwordKey, error) {
	derived, err := pbkdf2.Key(sha256.New, password, []byte(labelPasswordSalt), passwordKDFIterations, passwordKeySize)
	if err != nil {
		return passwordKey{}, err
	}
	var key passwordKey
	copy(key[:], derived)
	clear(derived)
	return key, nil
}

func derivePasswordKey(password string) (passwordKey, error) {
	return derivePasswordKeyContext(context.Background(), password)
}

func derivePasswordKeyContext(ctx context.Context, password string) (passwordKey, error) {
	if password == "" {
		return passwordKey{}, ErrEmptyPassword
	}
	fingerprint := passwordFingerprint(sha256.Sum256([]byte(password)))
	if key, ok := cachedPasswordKey(&fingerprint); ok {
		return key, nil
	}
	if err := ctx.Err(); err != nil {
		return passwordKey{}, handshakeIOError(err)
	}

	type result struct {
		key passwordKey
		err error
	}
	done := make(chan result, 1)
	go func() {
		key, err := stretchPassword(password)
		if err == nil {
			storePasswordKey(&fingerprint, key)
		}
		done <- result{key, err}
	}()
	select {
	case r := <-done:
		return r.key, r.err
	case <-ctx.Done():
		return passwordKey{}, handshakeIOError(ctx.Err())
	}
}

type sessionKeys struct {
	send          [sessionKeySize]byte
	recv          [sessionKeySize]byte
	peerRecvLimit int
}

type sessionSecrets struct {
	clientFinished [finishedSize]byte
	serverFinished [finishedSize]byte
	clientToServer [sessionKeySize]byte
	serverToClient [sessionKeySize]byte
}

func (s *sessionSecrets) wipe() {
	clear(s.clientFinished[:])
	clear(s.serverFinished[:])
	clear(s.clientToServer[:])
	clear(s.serverToClient[:])
}

func deriveSessionSecrets(isk *[cpaceISKSize]byte, clientHello, serverHello []byte) (sessionSecrets, error) {
	transcript := sha256.New()
	transcript.Write([]byte(labelTranscript))
	transcript.Write(clientHello)
	transcript.Write(serverHello)

	prk, err := hkdf.Extract(sha256.New, isk[:], transcript.Sum(nil))
	if err != nil {
		return sessionSecrets{}, err
	}
	defer clear(prk)

	var s sessionSecrets
	outputs := []struct {
		dst   []byte
		label string
	}{
		{s.clientFinished[:], labelClientFinished},
		{s.serverFinished[:], labelServerFinished},
		{s.clientToServer[:], labelClientToServer},
		{s.serverToClient[:], labelServerToClient},
	}
	for _, out := range outputs {
		derived, err := hkdf.Expand(sha256.New, prk, out.label, len(out.dst))
		if err != nil {
			return sessionSecrets{}, err
		}
		copy(out.dst, derived)
		clear(derived)
	}
	return s, nil
}

func putHelloPrefix(hello []byte, recvLimit int) {
	n := copy(hello, protocolMagic)
	hello[n] = protocolVersion
	binary.BigEndian.PutUint32(hello[n+1:helloPrefixSize], uint32(recvLimit))
}

func parseHelloPrefix(hello []byte) (int, error) {
	n := len(protocolMagic)
	if string(hello[:n]) != protocolMagic || hello[n] != protocolVersion {
		return 0, errBadHello
	}
	limit := int(binary.BigEndian.Uint32(hello[n+1 : helloPrefixSize]))
	if limit < minMessageLimit || limit > MaxMessageSize {
		return 0, fmt.Errorf("%w: peer message limit %d outside [%d, %d]", errBadHello, limit, minMessageLimit, MaxMessageSize)
	}
	return limit, nil
}

func handshakeIOError(err error) error {
	return fmt.Errorf("%w: %w", ErrHandshake, err)
}

func agreeSecrets(y *ristretto255.Scalar, peerPoint, clientHello, serverHello []byte) (sessionSecrets, error) {
	shared, err := cpaceSharedPoint(y, peerPoint)
	if err != nil {
		return sessionSecrets{}, fmt.Errorf("%w: %w", errBadHello, err)
	}
	defer clear(shared)
	sid := clientHello[clientSIDOffset:clientPointOffset]
	isk := cpaceISK(sid, shared,
		clientHello[clientPointOffset:], clientHello[:helloPrefixSize],
		serverHello[serverPointOffset:], serverHello[:helloPrefixSize])
	defer clear(isk[:])
	return deriveSessionSecrets(&isk, clientHello, serverHello)
}

func newEphemeral(pwKey *passwordKey, sid []byte) (*ristretto255.Scalar, []byte, error) {
	g, err := cpaceGenerator(pwKey[:], cpaceChannelID, sid)
	if err != nil {
		return nil, nil, err
	}
	y, err := cpaceSampleScalar()
	if err != nil {
		return nil, nil, err
	}
	return y, cpacePublicPoint(y, g), nil
}

func clientHandshake(conn io.ReadWriter, pwKey *passwordKey, recvLimit int) (sessionKeys, error) {
	var clientHello [clientHelloSize]byte
	putHelloPrefix(clientHello[:], recvLimit)
	sid := clientHello[clientSIDOffset:clientPointOffset]
	if _, err := rand.Read(sid); err != nil {
		return sessionKeys{}, err
	}
	y, point, err := newEphemeral(pwKey, sid)
	if err != nil {
		return sessionKeys{}, err
	}
	defer y.Zero()
	copy(clientHello[clientPointOffset:], point)

	if _, err := conn.Write(clientHello[:]); err != nil {
		return sessionKeys{}, handshakeIOError(err)
	}
	var serverHello [serverHelloSize]byte
	if _, err := io.ReadFull(conn, serverHello[:]); err != nil {
		return sessionKeys{}, handshakeIOError(err)
	}
	peerLimit, err := parseHelloPrefix(serverHello[:])
	if err != nil {
		return sessionKeys{}, err
	}
	secrets, err := agreeSecrets(y, serverHello[serverPointOffset:], clientHello[:], serverHello[:])
	if err != nil {
		return sessionKeys{}, err
	}
	defer secrets.wipe()
	if _, err := conn.Write(secrets.clientFinished[:]); err != nil {
		return sessionKeys{}, handshakeIOError(err)
	}
	var serverFinished [finishedSize]byte
	if _, err := io.ReadFull(conn, serverFinished[:]); err != nil {
		return sessionKeys{}, handshakeIOError(err)
	}
	if subtle.ConstantTimeCompare(serverFinished[:], secrets.serverFinished[:]) != 1 {
		return sessionKeys{}, errBadFinished
	}
	return sessionKeys{send: secrets.clientToServer, recv: secrets.serverToClient, peerRecvLimit: peerLimit}, nil
}

func serverHandshake(conn io.ReadWriter, pwKey *passwordKey, recvLimit int) (sessionKeys, error) {
	var clientHello [clientHelloSize]byte
	if _, err := io.ReadFull(conn, clientHello[:]); err != nil {
		return sessionKeys{}, handshakeIOError(err)
	}
	peerLimit, err := parseHelloPrefix(clientHello[:])
	if err != nil {
		return sessionKeys{}, err
	}
	y, point, err := newEphemeral(pwKey, clientHello[clientSIDOffset:clientPointOffset])
	if err != nil {
		return sessionKeys{}, err
	}
	defer y.Zero()
	var serverHello [serverHelloSize]byte
	putHelloPrefix(serverHello[:], recvLimit)
	copy(serverHello[serverPointOffset:], point)

	secrets, err := agreeSecrets(y, clientHello[clientPointOffset:], clientHello[:], serverHello[:])
	if err != nil {
		return sessionKeys{}, err
	}
	defer secrets.wipe()
	if _, err := conn.Write(serverHello[:]); err != nil {
		return sessionKeys{}, handshakeIOError(err)
	}
	var clientFinished [finishedSize]byte
	if _, err := io.ReadFull(conn, clientFinished[:]); err != nil {
		return sessionKeys{}, handshakeIOError(err)
	}
	if subtle.ConstantTimeCompare(clientFinished[:], secrets.clientFinished[:]) != 1 {
		return sessionKeys{}, errBadFinished
	}
	if _, err := conn.Write(secrets.serverFinished[:]); err != nil {
		return sessionKeys{}, handshakeIOError(err)
	}
	return sessionKeys{send: secrets.serverToClient, recv: secrets.clientToServer, peerRecvLimit: peerLimit}, nil
}
