/*
	Copyright NetFoundry, Inc.

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

package quic

import (
	"context"
	"crypto/tls"
	"io"
	"net"

	quicgo "github.com/lucas-clemente/quic-go"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/transport"
	"github.com/sirupsen/logrus"
)

func Listen(bindAddress, name string, i *identity.TokenId, incoming chan transport.Connection) (io.Closer, error) {
	log := pfxlog.ContextLogger(name + "/quic:" + bindAddress)

	tlsConfig := i.ServerTLSConfig()
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, "ziti-channel")
	listener, err := quicgo.ListenAddr(bindAddress, tlsConfig, &quicgo.Config{})
	if err != nil {
		return nil, err
	}

	go acceptLoop(log, name, listener, incoming)

	return listener, nil
}

func acceptLoop(log *logrus.Entry, name string, listener quicgo.Listener, incoming chan transport.Connection) {
	defer log.Error("exited")

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			if netErr, ok := err.(net.Error); ok && !netErr.Temporary() {
				log.WithField("err", err).Error("accept failed. Failure not recoverable. Exiting listen loop")
				return
			}
			log.WithField("err", err).Error("accept failed")
		} else {
			stream, err := session.AcceptStream(context.Background())
			if err != nil {
				log.WithField("err", err).Error("stream accept failed")

			} else {
				connection := &Connection{
					detail: &transport.ConnectionDetail{
						Address: "quic:" + session.RemoteAddr().String(),
						InBound: true,
						Name:    name,
					},
					session: session,
					stream:  stream,
				}
				incoming <- connection

				log.Infof("accepted connection from %s", session.RemoteAddr().String())
			}
		}
	}
}
