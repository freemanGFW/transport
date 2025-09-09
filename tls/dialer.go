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
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/identity"
	"github.com/openziti/transport/v2"
	"github.com/openziti/transport/v2/proxies"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/gmtls"
)

func Dial(a address, name string, i *identity.TokenId, timeout time.Duration, proxyConf *transport.ProxyConfiguration, protocols ...string) (transport.Conn, error) {
	return DialWithLocalBinding(a, name, "", i, timeout, proxyConf, protocols...)
}

func DialWithLocalBinding(a address, name, localBinding string, i *identity.TokenId, timeout time.Duration, proxyConf *transport.ProxyConfiguration, protocols ...string) (transport.Conn, error) {
	destination := a.bindableAddress()
	dialer, err := transport.NewDialerWithLocalBinding("tcp", timeout, localBinding)
	if err != nil {
		return nil, err
	}

	log := pfxlog.Logger().WithField("dest", destination)

	// 智能选择TLS配置：优先国密TLS，自动回退到标准TLS
	tlsCfg, isGM := getOptimalTLSConfig(i, a.hostname)
	if len(protocols) > 0 {
		if isGM {
			if gmConfig, ok := tlsCfg.(*gmtls.Config); ok {
				gmConfig.NextProtos = append(gmConfig.NextProtos, protocols...)
			}
		} else {
			if stdConfig, ok := tlsCfg.(*tls.Config); ok {
				stdConfig = stdConfig.Clone()
				stdConfig.NextProtos = append(stdConfig.NextProtos, protocols...)
				tlsCfg = stdConfig
			}
		}
	}

	var tlsConn interface{} // 支持标准TLS和国密TLS连接

	if proxyConf != nil && proxyConf.Type != transport.ProxyTypeNone {
		if proxyConf.Type == transport.ProxyTypeHttpConnect {
			log.Infof("using http connect proxy at %s", proxyConf.Address)
			proxyDialer := proxies.NewHttpConnectProxyDialer(dialer, proxyConf.Address, proxyConf.Auth, timeout)
			conn, err := proxyDialer.Dial("tcp", destination)
			if err != nil {
				return nil, err
			}

			if isGM {
				tlsConn = gmtls.Client(conn, tlsCfg.(*gmtls.Config))
			} else {
				tlsConn = tls.Client(conn, tlsCfg.(*tls.Config))
			}
		} else {
			return nil, errors.Errorf("unsupported proxy type %s", string(proxyConf.Type))
		}
	} else {
		if isGM {
			tlsConn, err = gmtls.DialWithDialer(dialer, "tcp", destination, tlsCfg.(*gmtls.Config))
		} else {
			tlsConn, err = tls.DialWithDialer(dialer, "tcp", destination, tlsCfg.(*tls.Config))
		}
		if err != nil {
			return nil, err
		}
	}

	// 记录连接状态信息并创建适当的Connection
	if stdConn, ok := tlsConn.(*tls.Conn); ok {
		log.Debugf("server provided [%d] certificates", len(stdConn.ConnectionState().PeerCertificates))
		return &Connection{
			detail: &transport.ConnectionDetail{
				Address: Type + ":" + destination,
				InBound: false,
				Name:    name,
			},
			Conn: stdConn,
		}, nil
	} else if gmConn, ok := tlsConn.(*gmtls.Conn); ok {
		log.Debugf("GM TLS connection established")
		// 为国密TLS连接创建包装器，使其兼容现有的Connection接口
		return &GMConnection{
			detail: &transport.ConnectionDetail{
				Address: Type + ":" + destination,
				InBound: false,
				Name:    name,
			},
			Conn: gmConn,
		}, nil
	}

	return nil, errors.New("unknown TLS connection type")
}

// getOptimalTLSConfig 获取最优的TLS配置（国密优先，自动回退）
func getOptimalTLSConfig(i *identity.TokenId, hostname string) (interface{}, bool) {
	// 检查是否有国密配置
	if gmConfig := loadGMTLSConfig(); gmConfig != nil {
		gmConfig.ServerName = hostname
		pfxlog.Logger().Debug("using GM TLS configuration")
		return gmConfig, true
	}

	// 回退到标准TLS
	tlsConfig := i.ClientTLSConfig()
	tlsConfig.ServerName = hostname
	pfxlog.Logger().Debug("using standard TLS configuration")
	return tlsConfig, false
}

// loadGMTLSConfig 加载国密TLS配置
func loadGMTLSConfig() *gmtls.Config {
	// 方法1：从环境变量加载
	if gmConfig := loadGMFromEnv(); gmConfig != nil {
		return gmConfig
	}

	// 方法2：从默认路径加载
	return loadGMFromDefaultPaths()
}

// loadGMFromEnv 从环境变量加载国密配置
func loadGMFromEnv() *gmtls.Config {
	certFile := os.Getenv("GMTLS_CERT_FILE")
	keyFile := os.Getenv("GMTLS_KEY_FILE")

	if certFile != "" && keyFile != "" {
		return createGMConfig(certFile, keyFile)
	}

	return nil
}

// loadGMFromDefaultPaths 从默认路径加载国密配置
func loadGMFromDefaultPaths() *gmtls.Config {
	defaultPaths := []struct {
		cert, key string
	}{
		{"./certs/gm-client.crt", "./certs/gm-client.key"},
		{"./gmtls/client.crt", "./gmtls/client.key"},
		{"/etc/ssl/gmtls/client.crt", "/etc/ssl/gmtls/client.key"},
		{"./gm.crt", "./gm.key"},
	}

	for _, paths := range defaultPaths {
		if fileExists(paths.cert) && fileExists(paths.key) {
			if config := createGMConfig(paths.cert, paths.key); config != nil {
				pfxlog.Logger().Infof("loaded GM TLS config from %s", paths.cert)
				return config
			}
		}
	}

	return nil
}

// createGMConfig 从证书文件创建国密TLS配置
func createGMConfig(certFile, keyFile string) *gmtls.Config {
	cert, err := gmtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		pfxlog.Logger().WithError(err).Debugf("failed to load GM certificate: %s, %s", certFile, keyFile)
		return nil
	}

	return &gmtls.Config{
		Certificates: []gmtls.Certificate{cert},
	}
}

// fileExists 检查文件是否存在
func fileExists(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}

// GMConnection 国密TLS连接包装器，实现transport.Conn接口
type GMConnection struct {
	detail *transport.ConnectionDetail
	Conn   *gmtls.Conn
}

func (c *GMConnection) Read(b []byte) (n int, err error) {
	return c.Conn.Read(b)
}

func (c *GMConnection) Write(b []byte) (n int, err error) {
	return c.Conn.Write(b)
}

func (c *GMConnection) Close() error {
	return c.Conn.Close()
}

func (c *GMConnection) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *GMConnection) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *GMConnection) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *GMConnection) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *GMConnection) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *GMConnection) Detail() *transport.ConnectionDetail {
	return c.detail
}

func (c *GMConnection) PeerCertificates() []*x509.Certificate {
	// 国密TLS的证书获取方式，具体实现取决于gmtls包的API
	// 这里提供一个兼容的实现
	return nil // 实际实现需要根据gmtls包的API来获取证书
}

func (c *GMConnection) Protocol() string {
	// 国密TLS的协议信息获取
	return "" // 实际实现需要根据gmtls包的API来获取协议信息
}
