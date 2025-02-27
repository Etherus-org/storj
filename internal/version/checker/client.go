// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package checker

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/zeebo/errs"
	"gopkg.in/spacemonkeygo/monkit.v2"

	"storj.io/storj/internal/version"
	"storj.io/storj/pkg/storj"
)

var (
	mon = monkit.Package()

	// Error is the error class for version control client errors.
	Error = errs.Class("version control client error")
)

// ClientConfig is the config struct for the version control client.
type ClientConfig struct {
	ServerAddress  string        `help:"server address to check its version against" default:"https://version.storj.io"`
	RequestTimeout time.Duration `help:"Request timeout for version checks" default:"0h1m0s"`
}

// Client defines helper methods for using version control server response data.
//
// architecture: Client
type Client struct {
	config ClientConfig
}

// New constructs a new verson control server client.
func New(config ClientConfig) *Client {
	return &Client{
		config: config,
	}
}

// All handles the HTTP request to gather the latest version information.
func (client *Client) All(ctx context.Context) (ver version.AllowedVersions, err error) {
	defer mon.Task()(&ctx)(&err)

	// Tune Client to have a custom Timeout (reduces hanging software)
	httpClient := http.Client{
		Timeout: client.config.RequestTimeout,
	}

	// New Request that used the passed in context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, client.config.ServerAddress, nil)
	if err != nil {
		return version.AllowedVersions{}, Error.Wrap(err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return version.AllowedVersions{}, Error.Wrap(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return version.AllowedVersions{}, Error.Wrap(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return version.AllowedVersions{}, Error.New("non-success http status code: %d; body: %s\n", resp.StatusCode, body)
	}

	err = json.NewDecoder(bytes.NewReader(body)).Decode(&ver)
	return ver, Error.Wrap(err)
}

// OldMinimum returns the version with the given name at the root-level of the version control response.
// NB: This will be deprecated eventually in favor of what is currently the `processes` root-level object.
func (client *Client) OldMinimum(ctx context.Context, serviceName string) (ver version.SemVer, err error) {
	defer mon.Task()(&ctx, serviceName)(&err)

	versions, err := client.All(ctx)
	if err != nil {
		return version.SemVer{}, Error.Wrap(err)
	}

	r := reflect.ValueOf(&versions)
	f := reflect.Indirect(r).FieldByName(serviceName).Interface()
	result, ok := f.(version.SemVer)
	if !ok {
		return version.SemVer{}, Error.New("invalid process name: %s", serviceName)
	}
	return result, nil
}

// Process returns the version info for the named process from the version control server response.
func (client *Client) Process(ctx context.Context, processName string) (process version.Process, err error) {
	defer mon.Task()(&ctx, processName)(&err)

	versions, err := client.All(ctx)
	if err != nil {
		return version.Process{}, Error.Wrap(err)
	}

	processesValue := reflect.ValueOf(versions.Processes)
	field := processesValue.FieldByName(strings.Title(processName))

	processNameErr := Error.New("invalid process name: %s\n", processName)
	if field == (reflect.Value{}) {
		return version.Process{}, processNameErr
	}

	process, ok := field.Interface().(version.Process)
	if !ok {
		return version.Process{}, processNameErr
	}
	return process, nil
}

// ShouldUpdate downloads the rollout state from the versioncontrol server and
// checks if a user with the given nodeID should update, and if so, to what version.
func (client *Client) ShouldUpdate(ctx context.Context, processName string, nodeID storj.NodeID) (_ bool, _ version.Version, err error) {
	defer mon.Task()(&ctx, processName)(&err)

	process, err := client.Process(ctx, processName)
	if err != nil {
		return false, version.Version{}, Error.Wrap(err)
	}

	shouldUpdate := version.ShouldUpdate(process.Rollout, nodeID)
	if shouldUpdate {
		return true, process.Suggested, nil
	}
	return false, version.Version{}, nil
}
