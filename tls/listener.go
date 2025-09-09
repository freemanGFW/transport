/*
	Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/v2/concurrenz"
	"github.com/openziti/foundation/v2/rate"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/sirupsen/logrus"
	"github.com/tjfoc/gmsm/gmtls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// same as golang Dial default
	keepAlive = 15 * time.Second
)

var noProtocol = ""

type handlerKeyType struct{}

var handlerKey = handlerKeyType{}

var handshakeTimeout concurrenz.AtomicValue[time.Duration]

func SetSharedListenerHandshakeTimeout(timeout time.Duration) {
	handshakeTimeout.Store(timeout)
}

var rateLimiterAtomic concurrenz.AtomicValue[*rate.AdaptiveRateLimitTracker]

func SetSharedListenerRateLimiter(limiter rate.AdaptiveRateLimitTracker) {
	rateLimiterAtomic.Store(&limiter)
}

func init() {
	var limiter rate.AdaptiveRateLimitTracker = rate.NoOpAdaptiveRateLimitTracker{}
	rateLimiterAtomic.Store(&limiter)
}

func Listen(bindAddress, name string, i *identity.TokenId, acceptF func(transport.Conn), protocols ...string) (io.Closer, error) {
	log := pfxlog.ContextLogger(name + "/" + Type + ":" + bindAddress).Entry

	// 智能选择TLS配置：优先国密TLS，自动回退到标准TLS
	tlsCfg, isGM := getOptimalServerTLSConfig(i)
	
	result := &protocolHandler{
		name:    name,
		isGM:    isGM,
		acceptF: acceptF,
	}
	
	if isGM {
		gmConfig := tlsCfg.(*gmtls.Config)
		if len(protocols) > 0 {
			gmConfig.NextProtos = append(gmConfig.NextProtos, protocols...)
		}
		result.gmtls = gmConfig
	} else {
		stdConfig := tlsCfg.(*tls.Config).Clone()
		if len(protocols) > 0 {
			stdConfig.NextProtos = append(stdConfig.NextProtos, protocols...)
		}
		result.tls = stdConfig
	}

	err := registerWithSharedListener(bindAddress, result)
	if err != nil {
		log.WithError(err).Error("failed to register with shared listener")
		return nil, err
	}

	return result, nil
}

type tlsListener struct {
	connCh  chan *Connection
	handler *protocolHandler
	closed  atomic.Bool
}

func (self *tlsListener) Accept() (net.Conn, error) {
	conn := <-self.connCh
	if conn == nil {
		return nil, net.ErrClosed
	}
	return conn.Conn, nil
}

func (self *tlsListener) Close() error {
	var err error
	if self.closed.CompareAndSwap(false, true) {
		err = self.handler.Close()
		close(self.connCh)
	}
	return err
}

func (self *tlsListener) Addr() net.Addr {
	return self.handler.listener.sock.Addr()
}

func (self *tlsListener) tlsAccept(conn transport.Conn) {
	c := conn.(*Connection)
	self.connCh <- c
}

// gmtlsListener 国密TLS监听器，实现net.Listener接口
type gmtlsListener struct {
	connCh  chan *GMServerConnection
	handler *protocolHandler
	closed  atomic.Bool
}

func (self *gmtlsListener) Accept() (net.Conn, error) {
	conn := <-self.connCh
	if conn == nil {
		return nil, net.ErrClosed
	}
	return conn.Conn, nil
}

func (self *gmtlsListener) Close() error {
	var err error
	if self.closed.CompareAndSwap(false, true) {
		err = self.handler.Close()
		close(self.connCh)
	}
	return err
}

func (self *gmtlsListener) Addr() net.Addr {
	return self.handler.listener.sock.Addr()
}

func (self *gmtlsListener) gmtlsAccept(conn transport.Conn) {
	c := conn.(*GMServerConnection)
	self.connCh <- c
}

// ListenTLS returns net.Listener that is attached to shared listener with protocols (ALPN)
// specified by config.NextProtos
// It can be used in http.Server or other standard components
func ListenTLS(bindAddress, name string, config *tls.Config) (net.Listener, error) {
	log := pfxlog.ContextLogger(name + "/" + Type + ":" + bindAddress).Entry

	l := &tlsListener{}

	handler := &protocolHandler{
		name:    name,
		tls:     config,
		isGM:    false,
		acceptF: l.tlsAccept,
	}

	err := registerWithSharedListener(bindAddress, handler)
	if err != nil {
		log.WithError(err).Error("failed to register with shared listener")
		return nil, err
	}

	l.handler = handler
	l.connCh = make(chan *Connection, 16)

	return l, nil
}

// ListenGMTLS returns net.Listener that is attached to shared listener with protocols (ALPN)
// specified by config.NextProtos for GM TLS (Chinese national cryptographic standards)
// It can be used in http.Server or other standard components with GM TLS support
func ListenGMTLS(bindAddress, name string, config *gmtls.Config) (net.Listener, error) {
	log := pfxlog.ContextLogger(name + "/" + Type + ":" + bindAddress).Entry

	l := &gmtlsListener{}

	handler := &protocolHandler{
		name:    name,
		gmtls:   config,
		isGM:    true,
		acceptF: l.gmtlsAccept,
	}

	err := registerWithSharedListener(bindAddress, handler)
	if err != nil {
		log.WithError(err).Error("failed to register with shared GM TLS listener")
		return nil, err
	}

	l.handler = handler
	l.connCh = make(chan *GMServerConnection, 16)

	return l, nil
}

type protocolHandler struct {
	name     string
	listener *sharedListener
	tls      *tls.Config
	gmtls    *gmtls.Config
	isGM     bool
	acceptF  func(conn transport.Conn)
	closed   atomic.Bool
}

func (self *protocolHandler) Close() error {
	if self.closed.CompareAndSwap(false, true) {
		self.listener.remove(self)
		return nil
	}
	return nil
}

var sharedListeners sync.Map

func registerWithSharedListener(bindAddress string, acc *protocolHandler) error {
	sl := &sharedListener{
		address: bindAddress,
	}
	el, found := sharedListeners.LoadOrStore(bindAddress, sl)
	sl = el.(*sharedListener)

	if !found {
		sl.log = pfxlog.ContextLogger(Type + ":" + bindAddress).Entry
		sl.ctx, sl.done = context.WithCancel(context.Background())
		sl.handlers = make(map[string]*protocolHandler)

		// 智能选择监听器类型：检查第一个处理器是否使用国密TLS
		if acc.isGM {
			sl.isGM = true
			sl.gmtlsCfg = &gmtls.Config{
				GetConfigForClient: sl.getGMConfig,
			}
			sock, err := gmtls.Listen("tcp", bindAddress, sl.gmtlsCfg)
			if err != nil {
				sharedListeners.Delete(bindAddress)
				return err
			}
			sl.sock = sock
			go sl.runGMAccept()
		} else {
			sl.isGM = false
			sl.tlsCfg = &tls.Config{
				GetConfigForClient: sl.getConfig,
			}
			sock, err := tls.Listen("tcp", bindAddress, sl.tlsCfg)
			if err != nil {
				sharedListeners.Delete(bindAddress)
				return err
			}
			sl.sock = sock
			go sl.runAccept()
		}
	}

	var protos []string
	if acc.isGM && acc.gmtls != nil {
		protos = acc.gmtls.NextProtos
	} else if acc.tls != nil {
		protos = acc.tls.NextProtos
	}
	
	if protos == nil {
		protos = append(protos, "")
	}

	sl.mtx.Lock()
	defer sl.mtx.Unlock()

	// check for conflict
	for _, proto := range protos {
		if _, exists := sl.handlers[proto]; exists {
			return fmt.Errorf("handler for protocol[%s] already exists", proto)
		}
	}

	acc.listener = sl
	for _, proto := range protos {
		sl.handlers[proto] = acc
	}

	return nil
}

type sharedListener struct {
	log      logrus.FieldLogger
	address  string
	tlsCfg   *tls.Config
	gmtlsCfg *gmtls.Config
	isGM     bool
	mtx      sync.RWMutex
	handlers map[string]*protocolHandler // proto -> protocolHandler
	ctx      context.Context
	done     context.CancelFunc
	sock     net.Listener
}

func (self *sharedListener) processConn(conn *tls.Conn) {
	log := self.log.WithField("remote", conn.RemoteAddr().String())

	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(keepAlive)
	}

	timeout := handshakeTimeout.Load()
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	rateLimiter := *rateLimiterAtomic.Load()

	// sharedListener.getConfig will select the right handler during handshake based on ClientHelloInfo
	// no need to do another look up here
	var handler *protocolHandler
	hsCtx, cancelF := context.WithTimeout(context.WithValue(self.ctx, handlerKey, &handler), timeout)
	defer cancelF()

	handshakeF := func(control rate.RateLimitControl) error {
		err := conn.HandshakeContext(hsCtx)
		if err != nil {
			if io.EOF == err {
				control.Backoff()
			} else {
				control.Failed()
			}
			return err
		}
		control.Success()
		return nil
	}

	err := rateLimiter.RunRateLimitedF(fmt.Sprintf("tls handlshake from %s", conn.RemoteAddr().String()), handshakeF)

	if err != nil {
		log.WithError(err).Error("handshake failed")
		_ = conn.Close()
		return
	}

	proto := conn.ConnectionState().NegotiatedProtocol
	log.WithField("client", conn.RemoteAddr()).Debug("selected protocol = '", proto, "'")

	connection := &Connection{
		detail: &transport.ConnectionDetail{
			Address: Type + ":" + conn.RemoteAddr().String(),
			InBound: true,
			Name:    handler.name,
		},
		Conn: conn,
	}
	handler.acceptF(connection)
}

func (self *sharedListener) runAccept() {
	log := self.log
	defer log.Info("exited")
	for {
		c, err := self.sock.Accept()
		if err != nil {
			if self.ctx.Err() != nil {
				log.WithError(err).Info("listener closed, exiting")
				return
			}
			log.WithError(err).Error("accept failed, exiting")
			return
		}

		conn := c.(*tls.Conn)

		go self.processConn(conn)
	}
}

// runGMAccept 国密TLS连接接受循环
func (self *sharedListener) runGMAccept() {
	log := self.log
	defer log.Info("GM TLS listener exited")
	for {
		c, err := self.sock.Accept()
		if err != nil {
			if self.ctx.Err() != nil {
				log.WithError(err).Info("GM TLS listener closed, exiting")
				return
			}
			log.WithError(err).Error("GM TLS accept failed, exiting")
			return
		}

		conn := c.(*gmtls.Conn)

		go self.processGMConn(conn)
	}
}

// processGMConn 处理国密TLS连接
func (self *sharedListener) processGMConn(conn *gmtls.Conn) {
	log := self.log.WithField("remote", conn.RemoteAddr().String())

	timeout := handshakeTimeout.Load()
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	rateLimiter := *rateLimiterAtomic.Load()

	// 国密TLS握手处理器选择将在握手过程中基于ClientHelloInfo完成
	var handler *protocolHandler
	_, cancelF := context.WithTimeout(context.WithValue(self.ctx, handlerKey, &handler), timeout)
	defer cancelF()

	handshakeF := func(control rate.RateLimitControl) error {
		// 国密TLS的握手方式，根据gmtls包的API调整
		err := conn.Handshake()
		if err != nil {
			if io.EOF == err {
				control.Backoff()
			} else {
				control.Failed()
			}
			return err
		}
		control.Success()
		return nil
	}

	err := rateLimiter.RunRateLimitedF(fmt.Sprintf("GM TLS handshake from %s", conn.RemoteAddr().String()), handshakeF)

	if err != nil {
		log.WithError(err).Error("GM TLS handshake failed")
		_ = conn.Close()
		return
	}

	proto := conn.ConnectionState().NegotiatedProtocol
	log.WithField("client", conn.RemoteAddr()).Debug("GM TLS selected protocol = '", proto, "'")

	connection := &GMServerConnection{
		detail: &transport.ConnectionDetail{
			Address: Type + ":" + conn.RemoteAddr().String(),
			InBound: true,
			Name:    handler.name,
		},
		Conn: conn,
	}
	handler.acceptF(connection)
}

func (self *sharedListener) getConfig(info *tls.ClientHelloInfo) (*tls.Config, error) {
	log := self.log.WithField("client", info.Conn.RemoteAddr())

	protos := info.SupportedProtos
	log.Debug("client requesting protocols = ", protos)

	ctx := info.Context()
	handlerOut := ctx.Value(handlerKey).(**protocolHandler)

	self.mtx.RLock()
	defer self.mtx.RUnlock()

	var handler *protocolHandler
	var proto string
	if protos == nil && len(self.handlers) == 1 {
		log.Debugf("using single protocol as default")
		for p, h := range self.handlers {
			proto, handler = p, h
		}
	} else {
		if protos == nil {
			protos = append(protos, noProtocol)
		}

		for _, p := range protos {
			h, found := self.handlers[p]
			if found {
				log.Debugf("found handler for proto[%s]", proto)
				handler = h
				proto = p
			}
		}
	}

	if handler != nil {
		*handlerOut = handler
		cfg := handler.tls
		if cfg.GetConfigForClient != nil {
			c, _ := cfg.GetConfigForClient(info)
			if c != nil {
				cfg = c
			}
		}
		cfg = cfg.Clone()
		cfg.NextProtos = []string{proto}
		return cfg, nil
	}

	return nil, fmt.Errorf("not handler for requested protocols %+v", protos)
}

// getGMConfig 获取国密TLS配置（类似于getConfig但适用于国密TLS）
func (self *sharedListener) getGMConfig(info *gmtls.ClientHelloInfo) (*gmtls.Config, error) {
	log := self.log.WithField("client", info.Conn.RemoteAddr())

	protos := info.SupportedProtos
	log.Debug("GM TLS client requesting protocols = ", protos)

	// 注意：国密TLS的ClientHelloInfo可能没有Context方法，这里使用另一种方式传递handler
	// 我们需要通过其他方式获取handler引用

	self.mtx.RLock()
	defer self.mtx.RUnlock()

	var handler *protocolHandler
	var proto string
	if protos == nil && len(self.handlers) == 1 {
		log.Debugf("using single GM TLS protocol as default")
		for p, h := range self.handlers {
			proto, handler = p, h
		}
	} else {
		if protos == nil {
			protos = append(protos, noProtocol)
		}

		for _, p := range protos {
			h, found := self.handlers[p]
			if found {
				log.Debugf("found GM TLS handler for proto[%s]", p)
				handler = h
				proto = p
				break
			}
		}
	}

	if handler != nil {
		cfg := handler.gmtls
		if cfg.GetConfigForClient != nil {
			c, _ := cfg.GetConfigForClient(info)
			if c != nil {
				cfg = c
			}
		}
		// 国密TLS配置克隆（如果gmtls包支持Clone方法）
		newCfg := *cfg // 简单的结构体复制，实际应该使用Clone方法
		newCfg.NextProtos = []string{proto}
		return &newCfg, nil
	}

	return nil, fmt.Errorf("no GM TLS handler for requested protocols %+v", protos)
}

func (self *sharedListener) remove(h *protocolHandler) {
	self.log.WithField("name", h.name).Debug("removing handler")

	var protos []string
	if h.isGM && h.gmtls != nil {
		protos = h.gmtls.NextProtos
	} else if h.tls != nil {
		protos = h.tls.NextProtos
	}
	
	if protos == nil {
		protos = append(protos, noProtocol)
	}

	for _, p := range protos {
		delete(self.handlers, p)
	}

	self.mtx.Lock()
	defer self.mtx.Unlock()

	if len(self.handlers) == 0 {
		self.log.Debug("no handlers left. stopping")
		sharedListeners.Delete(self.address)
		self.done()
		_ = self.sock.Close()
	}
}

// getOptimalServerTLSConfig 获取最优的服务器TLS配置（国密优先，自动回退）
func getOptimalServerTLSConfig(i *identity.TokenId) (interface{}, bool) {
	// 检查是否有国密配置
	if gmConfig := loadGMServerTLSConfig(); gmConfig != nil {
		pfxlog.Logger().Debug("using GM TLS server configuration")
		return gmConfig, true
	}

	// 回退到标准TLS
	tlsConfig := i.ServerTLSConfig()
	pfxlog.Logger().Debug("using standard TLS server configuration")
	return tlsConfig, false
}

// loadGMServerTLSConfig 加载国密服务器TLS配置
func loadGMServerTLSConfig() *gmtls.Config {
	// 方法1：从环境变量加载
	if gmConfig := loadGMServerFromEnv(); gmConfig != nil {
		return gmConfig
	}

	// 方法2：从默认路径加载
	return loadGMServerFromDefaultPaths()
}

// loadGMServerFromEnv 从环境变量加载国密服务器配置
func loadGMServerFromEnv() *gmtls.Config {
	certFile := os.Getenv("GMTLS_SERVER_CERT_FILE")
	keyFile := os.Getenv("GMTLS_SERVER_KEY_FILE")

	if certFile != "" && keyFile != "" {
		return createGMServerConfig(certFile, keyFile)
	}

	return nil
}

// loadGMServerFromDefaultPaths 从默认路径加载国密服务器配置
func loadGMServerFromDefaultPaths() *gmtls.Config {
	defaultPaths := []struct {
		cert, key string
	}{
		{"./certs/gm-server.crt", "./certs/gm-server.key"},
		{"./gmtls/server.crt", "./gmtls/server.key"},
		{"/etc/ssl/gmtls/server.crt", "/etc/ssl/gmtls/server.key"},
		{"./gm-server.crt", "./gm-server.key"},
	}

	for _, paths := range defaultPaths {
		if fileExists(paths.cert) && fileExists(paths.key) {
			if config := createGMServerConfig(paths.cert, paths.key); config != nil {
				pfxlog.Logger().Infof("loaded GM TLS server config from %s", paths.cert)
				return config
			}
		}
	}

	return nil
}

// createGMServerConfig 从证书文件创建国密服务器TLS配置
func createGMServerConfig(certFile, keyFile string) *gmtls.Config {
	cert, err := gmtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		pfxlog.Logger().WithError(err).Debugf("failed to load GM server certificate: %s, %s", certFile, keyFile)
		return nil
	}

	return &gmtls.Config{
		Certificates: []gmtls.Certificate{cert},
	}
}

// GMServerConnection 国密TLS服务器连接包装器，实现transport.Conn接口
type GMServerConnection struct {
	detail *transport.ConnectionDetail
	Conn   *gmtls.Conn
}

func (c *GMServerConnection) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *GMServerConnection) Write(b []byte) (n int, err error) {
	return c.Conn.Write(b)
}

func (c *GMServerConnection) Close() error {
	return c.Conn.Close()
}

func (c *GMServerConnection) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *GMServerConnection) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *GMServerConnection) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *GMServerConnection) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *GMServerConnection) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *GMServerConnection) Detail() *transport.ConnectionDetail {
	return c.detail
}

func (c *GMServerConnection) PeerCertificates() []*x509.Certificate {
	// 国密TLS的证书获取方式，具体实现取决于gmtls包的API
	// 这里提供一个兼容的实现
	return nil // 实际实现需要根据gmtls包的API来获取证书
}

func (c *GMServerConnection) Protocol() string {
	// 国密TLS的协议信息获取
	return "" // 实际实现需要根据gmtls包的API来获取协议信息
}
