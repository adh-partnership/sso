/*
 * Copyright ADH Partnership
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package config

import (
	"errors"
	"os"

	"dario.cat/mergo"
	"github.com/adh-partnership/api/pkg/config"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"sigs.k8s.io/yaml"
)

var (
	ErrorMissingConfig    = errors.New("missing configuration")
	ErrorMissingJWKConfig = errors.New("missing JWKS configuration")
	ErrorInvalidJWKs      = errors.New("invalid JWKS")
	ErrorInvalidOAuth     = errors.New("invalid OAuth configuration")
)

type cfg struct {
	JWKsRaw  string
	JWKs     *jwk.Set
	Database config.ConfigDatabase
	OAuth    ConfigOAuth
	Server   ConfigServer
}

type ConfigOAuth struct {
	BaseURL       string   `json:"base_url"`
	AuthorizePath string   `json:"authorize_path"`
	TokenPath     string   `json:"token_path"`
	UserInfoPath  string   `json:"user_info_path"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	ClientScopes  []string `json:"client_scopes"`
}

type ConfigServer struct {
	Port         string `json:"port"`
	Mode         string `json:"mode"` // accepted values: plain, tls, h2c
	SSLCert      string `json:"ssl_cert"`
	SSLKey       string `json:"ssl_key"`
	CookieName   string `json:"cookie_name"`
	CookieSecret string `json:"cookie_secret"`
}

var Cfg = &cfg{
	JWKsRaw: "",
	JWKs:    nil,
	Database: config.ConfigDatabase{
		Host:     "localhost",
		Port:     "3306",
		User:     "root",
		Password: "root",
		Database: "sso",
	},
	OAuth: ConfigOAuth{
		BaseURL:       "https://auth.vatsim.net",
		AuthorizePath: "/oauth/authorize",
		TokenPath:     "/oauth/token",
		UserInfoPath:  "/api/user",
		ClientScopes: []string{
			"full_name",
			"email",
			"vatsim_details",
		},
	},
	Server: ConfigServer{
		Port:       "3000",
		Mode:       "plain",
		CookieName: "adh-sso",
	},
}

func LoadConfig(config_file, jwks_file string) error {
	if _, err := os.Stat(config_file); os.IsNotExist(err) {
		return ErrorMissingConfig
	}

	if _, err := os.Stat(jwks_file); os.IsNotExist(err) {
		return ErrorMissingJWKConfig
	}

	config_data, err := os.ReadFile(config_file)
	if err != nil {
		return err
	}
	c := &cfg{}
	err = yaml.Unmarshal(config_data, c)
	if err != nil {
		return err
	}

	jwks_data, err := os.ReadFile(jwks_file)
	if err != nil {
		return err
	}
	c.JWKsRaw = string(jwks_data)
	set, err := jwk.ParseString(c.JWKsRaw)
	if err != nil {
		return err
	}
	c.JWKs = &set

	if err = mergo.Merge(Cfg, c, mergo.WithOverride); err != nil {
		return err
	}

	return nil
}

func (c *cfg) Validate() error {
	if c.JWKsRaw == "" {
		return ErrorInvalidJWKs
	}

	if c.JWKs == nil {
		return ErrorInvalidJWKs
	}

	if c.OAuth.ClientID == "" || c.OAuth.ClientSecret == "" {
		return ErrorInvalidOAuth
	}

	return nil
}
