// Package txn2 implements PasswordConnector.
package txn2

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"github.com/txn2/provision"
)

// PasswordConfig holds the configuration which prompts for a supplied
// username and password used to contact AuthService.
type PasswordConfig struct {
	AuthService string `json:"authService"`
}

// Open returns an authentication strategy which prompts for a username and password.
func (c *PasswordConfig) Open(id string, logger log.Logger) (connector.Connector, error) {
	return &passwordConnector{
		AuthService: c.AuthService,
		logger:      logger}, nil
}

type passwordConnector struct {
	AuthService string
	logger      log.Logger
}

func (p passwordConnector) Close() error { return nil }

type TXN2Credentials struct {
	Id       string `json:"id"`
	Password string `json:"password"`
}

func (p passwordConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {

	url := p.AuthService + "/user"
	ipc := &TXN2Credentials{
		Id:       username,
		Password: password,
	}

	ipcJson, err := json.Marshal(ipc)
	if err != nil {
		p.logger.Error("Unable to marshall login: ", err.Error())
		return identity, false, nil
	}

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(ipcJson))

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("User-Agent", "txn2/dex")

	res, _ := http.DefaultClient.Do(req)
	if res.StatusCode != http.StatusOK {
		p.logger.Warn("Got non-200 from auth: ", res.StatusCode)
		return identity, false, nil
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	provisonUserAck := &provision.UserTokenResultAck{}
	err = json.Unmarshal(body, provisonUserAck)
	if err != nil {
		p.logger.Error("Unable to Unmarshal auth response: ", err.Error())
		return identity, false, nil
	}

	provisionUser := provisonUserAck.Payload.User

	return connector.Identity{
		UserID:        provisionUser.Id,
		Username:      provisionUser.Id,
		Email:         provisionUser.Id,
		EmailVerified: true,
	}, true, nil
}

func (p passwordConnector) Prompt() string { return "" }

func (p passwordConnector) Refresh(_ context.Context, _ connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	return identity, nil
}
