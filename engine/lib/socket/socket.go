package socket

import (
	"io"
	"io/ioutil"
	"net"
	"time"

	"zeroScannerGo/lib/dnscache"
)

var resolver *dnscache.Resolver

func SetDnsCache(dnsResolver *dnscache.Resolver) {
	resolver = dnsResolver
}

// 参见net包中Dial方法对network的定义
func New(network string) *Socket {
	s := new(Socket)
	s.network = network
	s.timeout = time.Second * 30
	if resolver != nil {
		s.resolver = resolver
	}
	return s
}

type Socket struct {
	network      string
	conn         net.Conn
	resolver     *dnscache.Resolver
	timeout      time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (s *Socket) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *Socket) SetReadTimeout(timeout time.Duration) {
	s.readTimeout = timeout
}

func (s *Socket) SetWriteTimeout(timeout time.Duration) {
	s.writeTimeout = timeout
}

func (s *Socket) SetReadAndWriteTimeout(timeout time.Duration) {
	s.readTimeout = timeout
	s.writeTimeout = timeout
}

func (s *Socket) SetDnsCache(dnsResolver *dnscache.Resolver) {
	s.resolver = resolver
}

func (s *Socket) Connect(host, port string) error {
	if s.resolver != nil {
		var err error
		host, err = s.resolver.FetchOneString(host)
		if err != nil {
			return err
		}
	}

	conn, err := net.DialTimeout(s.network, net.JoinHostPort(host, port), s.timeout)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

func (s *Socket) Write(b []byte) (int, error) {
	if s.writeTimeout > 0 {
		s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	}
	return s.conn.Write(b)
}

// 阻塞，读取所有的数据，直到EOF或者超时
func (s *Socket) Read() ([]byte, error) {
	if s.readTimeout > 0 {
		s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	}
	return ioutil.ReadAll(s.conn)
}

// 不阻塞，读到的数据有可能小于给定的n值
func (s *Socket) ReadN(n int) ([]byte, error) {
	if s.readTimeout > 0 {
		s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	}
	buf := make([]byte, n)
	c, err := s.conn.Read(buf)
	return buf[:c], err
}

// 阻塞，直到读到给定的数据长度或者超时
func (s *Socket) ReadAtLeast(n int64) ([]byte, error) {
	if s.readTimeout > 0 {
		s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	}
	return ioutil.ReadAll(io.LimitReader(s.conn, n))
}

func (s *Socket) Close() error {
	return s.conn.Close()
}
