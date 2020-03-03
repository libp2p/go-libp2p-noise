package noise

import (
	"context"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/sec"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"testing"
	"time"
)

func makeTransport(b *testing.B) *Transport {
	b.Helper()

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 256)
	if err != nil {
		b.Fatal(err)
	}
	tpt, err := New(priv)
	if err != nil {
		b.Fatalf("error constructing transport: %v", err)
	}
	return tpt
}

type benchenv struct {
	*testing.B

	initTpt *Transport
	respTpt *Transport
	rndSrc  rand.Source
}

func setupEnv(b *testing.B) *benchenv {
	b.StopTimer()
	defer b.StartTimer()
	initTpt := makeTransport(b)
	respTpt := makeTransport(b)

	return &benchenv{
		B:       b,
		initTpt: initTpt,
		respTpt: respTpt,
		rndSrc:  rand.NewSource(42),
	}
}

func (b benchenv) connect(stopTimer bool) (*secureSession, *secureSession) {
	initConn, respConn := net.Pipe()

	if stopTimer {
		b.StopTimer()
		defer b.StartTimer()
	}

	var initSession sec.SecureConn
	var initErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		initSession, initErr = b.initTpt.SecureOutbound(context.TODO(), initConn, b.respTpt.localID)
	}()

	respSession, respErr := b.respTpt.SecureInbound(context.TODO(), respConn)
	<-done

	if initErr != nil {
		b.Fatal(initErr)
	}

	if respErr != nil {
		b.Fatal(respErr)
	}

	return initSession.(*secureSession), respSession.(*secureSession)
}

func drain(r io.Reader, done chan<- error) {
	_, err := io.Copy(ioutil.Discard, r)
	done <- err
}

func sink(dst io.WriteCloser, src io.Reader, done chan<- error) {
	_, err := io.Copy(dst, src)
	if err != nil {
		done <- err
	}
	done <- dst.Close()
}

func pipeRandom(src rand.Source, w io.WriteCloser, r io.Reader, n int64) error {
	rnd := rand.New(src)
	lr := io.LimitReader(rnd, n)

	writeCh := make(chan error, 1)
	readCh := make(chan error, 1)

	go sink(w, lr, writeCh)
	go drain(r, readCh)

	writeDone := false
	readDone := false
	for !(readDone && writeDone) {
		select {
		case err := <-readCh:
			if err != nil && err != io.EOF {
				return err
			}
			readDone = true
		case err := <-writeCh:
			if err != nil && err != io.EOF {
				return err
			}
			writeDone = true
		}
	}

	return nil
}

func benchDataTransfer(b *benchenv, size int64) {
	var totalBytes int64
	var totalTime time.Duration
	for i := 0; i < b.N; i++ {
		initSession, respSession := b.connect(true)

		start := time.Now()
		err := pipeRandom(b.rndSrc, initSession, respSession, size)
		if err != nil {
			b.Fatalf("error sending random data: %s", err)
		}
		elapsed := time.Since(start)
		totalTime += elapsed
		totalBytes += size
	}
	bytesPerSec := float64(totalBytes) / totalTime.Seconds()
	b.ReportMetric(bytesPerSec, "bytes/sec")
}

func BenchmarkTransfer1MB(b *testing.B) {
	benchDataTransfer(setupEnv(b), 1024*1024)
}

func BenchmarkTransfer100MB(b *testing.B) {
	benchDataTransfer(setupEnv(b), 1024*1024*100)
}

func BenchmarkTransfer500Mb(b *testing.B) {
	benchDataTransfer(setupEnv(b), 1024*1024*500)
}

func (b benchenv) benchHandshake() {
	for i := 0; i < b.N; i++ {
		i, r := b.connect(false)
		b.StopTimer()
		err := i.Close()
		if err != nil {
			b.Errorf("error closing session: %s", err)
		}
		err = r.Close()
		if err != nil {
			b.Errorf("error closing session: %s", err)
		}
		b.StartTimer()
	}
}

func BenchmarkHandshakeXX(b *testing.B) {
	env := setupEnv(b)
	env.benchHandshake()
}
