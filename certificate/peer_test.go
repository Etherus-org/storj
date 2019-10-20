// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package certificate_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/zeebo/errs"
	"net"
	"storj.io/storj/storage"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"storj.io/storj/certificate"
	"storj.io/storj/certificate/authorization"
	"storj.io/storj/certificate/certificateclient"
	"storj.io/storj/internal/testcontext"
	"storj.io/storj/internal/testidentity"
	"storj.io/storj/pkg/identity"
	"storj.io/storj/pkg/pb"
	"storj.io/storj/pkg/peertls/tlsopts"
	"storj.io/storj/pkg/pkcrypto"
	"storj.io/storj/pkg/rpc"
	"storj.io/storj/pkg/rpc/rpcpeer"
	"storj.io/storj/pkg/server"
	"storj.io/storj/pkg/storj"
)

func TestCertificateSigner_Sign_E2E_error(t *testing.T) {
	testidentity.SignerVersionsTest(t, func(t *testing.T, _ storj.IDVersion, signer *identity.FullCertificateAuthority) {
		testidentity.CompleteIdentityVersionsTest(t, func(t *testing.T, _ storj.IDVersion, serverIdent *identity.FullIdentity) {
			testidentity.CompleteIdentityVersionsTest(t, func(t *testing.T, _ storj.IDVersion, clientIdent *identity.FullIdentity) {
				scenarios := []struct {
					name     string
					errClass errs.Class
					internal bool
				}{
					// custom identity
					//{
					//	"invalid difficulty",
					//	authorization.Error,
					//	false,
					//},
					// no client
					//{
					//	"invalid timestamp",
					//	authorization.Error,
					//	false,
					//},
					{
						"invalid token",
						authorization.Error,
						false,
					},
					{
						"db error",
						authorization.ErrDB,
						true,
					},
					{
						"invalid certificate",
						authorization.Error,
						false,
					},
				}

				ctx := testcontext.New(t)
				defer ctx.Cleanup()

				caCert := ctx.File("ca.cert")
				caKey := ctx.File("ca.key")
				//userID := "user@mail.test"
				signerCAConfig := identity.FullCAConfig{
					CertPath: caCert,
					KeyPath:  caKey,
				}
				err := signerCAConfig.Save(signer)
				require.NoError(t, err)

				authorizationsCfg := authorization.DBConfig{
					URL: "bolt://" + ctx.File("authorizations.db"),
				}

				authDB, err := authorization.NewDBFromCfg(authorizationsCfg)
				require.NoError(t, err)
				require.NotNil(t, authDB)

				auths, err := authDB.Create(ctx, "user@mail.test", len(scenarios))
				require.NoError(t, err)
				require.NotEmpty(t, auths)

				certificatesCfg := certificate.Config{
					Signer: signerCAConfig,
					Server: server.Config{
						Address: "127.0.0.1:0",
						Config: tlsopts.Config{
							PeerIDVersions: "*",
						},
					},
					AuthorizationAddr: "127.0.0.1:0",
				}

				peer, err := certificate.New(zaptest.NewLogger(t), serverIdent, signer, authDB, nil, &certificatesCfg)
				require.NoError(t, err)
				require.NotNil(t, peer)

				ctx.Go(func() error {
					err := peer.Run(ctx)
					assert.NoError(t, err)
					return err
				})
				defer ctx.Check(peer.Close)

				tlsOptions, err := tlsopts.NewOptions(clientIdent, tlsopts.Config{
					PeerIDVersions: "*",
				}, nil)
				require.NoError(t, err)

				dialer := rpc.NewDefaultDialer(tlsOptions)

				client, err := certificateclient.New(ctx, dialer, peer.Server.Addr().String())
				require.NoError(t, err)
				require.NotNil(t, client)
				defer ctx.Check(client.Close)

				// claim first authorization
				signedChainBytes, err := client.Sign(ctx, auths[0].Token.String())
				require.NoError(t, err)
				require.NotEmpty(t, signedChainBytes)

				t.Run("already claimed", func(t *testing.T) {
					signedChainBytes, err := client.Sign(ctx, auths[0].Token.String())
					require.Error(t, err)
					require.Empty(t, signedChainBytes)
					require.Contains(t, err.Error(), authorization.Error.New("").Error())
				})

				t.Run("invalid difficulty", func(t *testing.T) {
					authorizationsCfg := authorization.DBConfig{
						URL: "bolt://" + ctx.File("authorizations2.db"),
					}

					authDB, err := authorization.NewDBFromCfg(authorizationsCfg)
					require.NoError(t, err)
					require.NotNil(t, authDB)

					certificatesCfg := certificate.Config{
						MinDifficulty: 99,
						Signer:        signerCAConfig,
						Server: server.Config{
							Address: "127.0.0.1:0",
							Config: tlsopts.Config{
								PeerIDVersions: "*",
							},
						},
						AuthorizationAddr: "127.0.0.1:0",
					}

					peer, err := certificate.New(zaptest.NewLogger(t), serverIdent, signer, authDB, nil, &certificatesCfg)
					require.NoError(t, err)
					require.NotNil(t, peer)

					ctx.Go(func() error {
						err := peer.Run(ctx)
						assert.NoError(t, err)
						return err
					})
					defer ctx.Check(peer.Close)

					client, err := certificateclient.New(ctx, dialer, peer.Server.Addr().String())
					require.NoError(t, err)
					require.NotNil(t, client)
					defer ctx.Check(client.Close)

					signedChainBytes, err := client.Sign(ctx, auths[0].Token.String())
					require.Error(t, err)
					require.Empty(t, signedChainBytes)
					require.Contains(t, err.Error(), authorization.Error.New("").Error())
				})

				t.Run("db error", func(t *testing.T) {
					authorizationsCfg := authorization.DBConfig{
						URL: "bolt://" + ctx.File("authorizations3.db"),
					}

					authDB, err := authorization.NewDBFromCfg(authorizationsCfg)
					require.NoError(t, err)
					require.NotNil(t, authDB)

					certificatesCfg := certificate.Config{
						Signer:        signerCAConfig,
						Server: server.Config{
							Address: "127.0.0.1:0",
							Config: tlsopts.Config{
								PeerIDVersions: "*",
							},
						},
						AuthorizationAddr: "127.0.0.1:0",
					}

					peer, err := certificate.New(zaptest.NewLogger(t), serverIdent, signer, authDB, nil, &certificatesCfg)
					require.NoError(t, err)
					require.NotNil(t, peer)

					cancelableCtx, cancel := context.WithCancel(ctx)
					ctx.Go(func() error {
						err := peer.Run(cancelableCtx)
						assert.NoError(t, err)
						return err
					})
					defer ctx.Check(peer.Close)
					_ = cancel
					//defer cancel()

					//err = authDB.Close()
					//require.NoError(t, err)

					client, err := certificateclient.New(ctx, dialer, peer.Server.Addr().String())
					require.NoError(t, err)
					require.NotNil(t, client)
					defer ctx.Check(client.Close)

					signedChainBytes, err := client.Sign(ctx, auths[0].Token.String())
					require.Error(t, err)
					require.Empty(t, signedChainBytes)
					require.Contains(t, err.Error(), authorization.ErrDB.New("").Error())
					require.NotContains(t, err.Error(), storage.ErrKeyNotFound.New("").Error())
				})
			})
		})
	})
}

func TestCertificateSigner_Sign_E2E(t *testing.T) {
	testidentity.SignerVersionsTest(t, func(t *testing.T, _ storj.IDVersion, signer *identity.FullCertificateAuthority) {
		testidentity.CompleteIdentityVersionsTest(t, func(t *testing.T, _ storj.IDVersion, serverIdent *identity.FullIdentity) {
			testidentity.CompleteIdentityVersionsTest(t, func(t *testing.T, _ storj.IDVersion, clientIdent *identity.FullIdentity) {
				ctx := testcontext.New(t)
				defer ctx.Cleanup()

				caCert := ctx.File("ca.cert")
				caKey := ctx.File("ca.key")
				userID := "user@mail.test"
				signerCAConfig := identity.FullCAConfig{
					CertPath: caCert,
					KeyPath:  caKey,
				}
				err := signerCAConfig.Save(signer)
				require.NoError(t, err)

				authorizationsCfg := authorization.DBConfig{
					URL: "bolt://" + ctx.File("authorizations.db"),
				}

				authDB, err := authorization.NewDBFromCfg(authorizationsCfg)
				require.NoError(t, err)
				require.NotNil(t, authDB)

				auths, err := authDB.Create(ctx, "user@mail.test", 1)
				require.NoError(t, err)
				require.NotEmpty(t, auths)

				certificatesCfg := certificate.Config{
					Signer: signerCAConfig,
					Server: server.Config{
						Address: "127.0.0.1:0",
						Config: tlsopts.Config{
							PeerIDVersions: "*",
						},
					},
					AuthorizationAddr: "127.0.0.1:0",
				}

				peer, err := certificate.New(zaptest.NewLogger(t), serverIdent, signer, authDB, nil, &certificatesCfg)
				require.NoError(t, err)
				require.NotNil(t, peer)

				ctx.Go(func() error {
					err := peer.Run(ctx)
					assert.NoError(t, err)
					return err
				})
				defer ctx.Check(peer.Close)

				tlsOptions, err := tlsopts.NewOptions(clientIdent, tlsopts.Config{
					PeerIDVersions: "*",
				}, nil)
				require.NoError(t, err)

				dialer := rpc.NewDefaultDialer(tlsOptions)

				client, err := certificateclient.New(ctx, dialer, peer.Server.Addr().String())
				require.NoError(t, err)
				require.NotNil(t, client)
				defer ctx.Check(client.Close)

				signedChainBytes, err := client.Sign(ctx, auths[0].Token.String())
				require.NoError(t, err)
				require.NotEmpty(t, signedChainBytes)

				signedChain, err := pkcrypto.CertsFromDER(signedChainBytes)
				require.NoError(t, err)

				assert.Equal(t, clientIdent.CA.RawTBSCertificate, signedChain[0].RawTBSCertificate)
				assert.Equal(t, signer.Cert.Raw, signedChainBytes[1])
				// TODO: test scenario with rest chain
				//assert.Equal(t, signingCA.RawRestChain(), signedChainBytes[1:])

				err = signedChain[0].CheckSignatureFrom(signer.Cert)
				require.NoError(t, err)

				err = peer.Close()
				assert.NoError(t, err)

				// NB: re-open after closing for server
				authDB, err = authorization.NewDBFromCfg(authorizationsCfg)
				require.NoError(t, err)
				defer ctx.Check(authDB.Close)
				require.NotNil(t, authDB)

				updatedAuths, err := authDB.Get(ctx, userID)
				require.NoError(t, err)
				require.NotEmpty(t, updatedAuths)
				require.NotNil(t, updatedAuths[0].Claim)

				now := time.Now().Unix()
				claim := updatedAuths[0].Claim

				listenerHost, _, err := net.SplitHostPort(peer.Server.Addr().String())
				require.NoError(t, err)
				claimHost, _, err := net.SplitHostPort(claim.Addr)
				require.NoError(t, err)

				assert.Equal(t, listenerHost, claimHost)
				assert.Equal(t, signedChainBytes, claim.SignedChainBytes)
				assert.Condition(t, func() bool {
					return now-10 < claim.Timestamp &&
						claim.Timestamp < now+10
				})
			})
		})
	})
}

func TestCertificateSigner_Sign(t *testing.T) {
	testidentity.SignerVersionsTest(t, func(t *testing.T, _ storj.IDVersion, ca *identity.FullCertificateAuthority) {
		testidentity.CompleteIdentityVersionsTest(t, func(t *testing.T, _ storj.IDVersion, ident *identity.FullIdentity) {
			ctx := testcontext.New(t)
			defer ctx.Cleanup()

			userID := "user@mail.test"
			// TODO: test with all types of authorization DBs (bolt, redis, etc.)
			authDB, err := authorization.NewDB("bolt://"+ctx.File("authorizations.db"), false)
			require.NoError(t, err)
			defer ctx.Check(authDB.Close)
			require.NotNil(t, authDB)

			auths, err := authDB.Create(ctx, userID, 1)
			require.NoError(t, err)
			require.NotEmpty(t, auths)

			expectedAddr := &net.TCPAddr{
				IP:   net.ParseIP("1.2.3.4"),
				Port: 5,
			}
			peer := &rpcpeer.Peer{
				Addr: expectedAddr,
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{ident.Leaf, ident.CA},
				},
			}
			peerCtx := rpcpeer.NewContext(ctx, peer)

			certSigner := certificate.NewEndpoint(zaptest.NewLogger(t), ca, authDB, 0)
			req := pb.SigningRequest{
				Timestamp: time.Now().Unix(),
				AuthToken: auths[0].Token.String(),
			}
			res, err := certSigner.Sign(peerCtx, &req)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.NotEmpty(t, res.Chain)

			signedChain, err := pkcrypto.CertsFromDER(res.Chain)
			require.NoError(t, err)

			assert.Equal(t, ident.CA.RawTBSCertificate, signedChain[0].RawTBSCertificate)
			assert.Equal(t, ca.Cert.Raw, signedChain[1].Raw)
			// TODO: test scenario with rest chain
			//assert.Equal(t, signingCA.RawRestChain(), res.Chain[1:])

			err = signedChain[0].CheckSignatureFrom(ca.Cert)
			require.NoError(t, err)

			updatedAuths, err := authDB.Get(ctx, userID)
			require.NoError(t, err)
			require.NotEmpty(t, updatedAuths)
			require.NotNil(t, updatedAuths[0].Claim)

			now := time.Now().Unix()
			claim := updatedAuths[0].Claim
			assert.Equal(t, expectedAddr.String(), claim.Addr)
			assert.Equal(t, res.Chain, claim.SignedChainBytes)
			assert.Condition(t, func() bool {
				return now-authorization.MaxClaimDelaySeconds < claim.Timestamp &&
					claim.Timestamp < now+authorization.MaxClaimDelaySeconds
			})
		})
	})
}
