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

	quicgo "github.com/lucas-clemente/quic-go"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/transport"
)

// Dial a connection over QUIC.
//
func Dial(destination, name string, i *identity.TokenId) (transport.Connection, error) {
	tlsConfig := i.ClientTLSConfig()
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, "ziti-channel")
	session, err := quicgo.DialAddr(destination, tlsConfig, &quicgo.Config{})
	if err != nil {
		return nil, err
	}

	detail := &transport.ConnectionDetail{
		Address: "quic:" + destination,
		InBound: false,
		Name:    name,
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return &Connection{
			detail:  detail,
			session: session,
		}, err
	}

	return &Connection{
		detail:  detail,
		session: session,
		stream:  stream,
	}, nil
}
