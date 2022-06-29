/*
   ZAU Single Sign-On
   Copyright (C) 2021  Daniel A. Hawton <daniel@hawton.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package v1

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/kzdv/sso/pkg/login"
	"github.com/kzdv/sso/pkg/tokens"
	utils "github.com/kzdv/sso/pkg/utils"
	"hawton.dev/log4g"
)

type TokenResponse struct {
	AccessToken         string `json:"access_token"`
	ExpiresIn           int    `json:"expires_in"`
	TokenType           string `json:"token_type"`
	IdToken             string `json:"id_token"`
	RefreshToken        string `json:"refresh_token"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

func PostToken(c *gin.Context) {
	treq := login.TokenRequest{}
	if err := c.ShouldBind(&treq); err != nil {
		log4g.Category("controllers/token").Error("Invalid request, missing field(s)")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	if treq.ClientId == "" || treq.ClientSecret == "" {
		if c.GetHeader("Authorization") == "" {
			log4g.Category("controllers/token").Error("Invalid request, missing field(s)")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		} else {
			auth := strings.Split(c.GetHeader("Authorization"), " ")[1]
			authBytes, err := base64.URLEncoding.DecodeString(auth)
			if err != nil {
				log4g.Category("controllers/token").Error("Failed base64 decoding %s %s", c.GetHeader("Authorization"), err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
				return
			}
			authslice := strings.SplitN(string(authBytes), ":", 2)
			treq.ClientId = authslice[0]
			treq.ClientSecret = authslice[1]
		}
	}

	l, user, err := login.HandleGrantType(treq)
	if err != nil {
		log4g.Category("controllers/token").Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(treq.Scope) == 0 {
		treq.Scope = strings.Split(l.Scope, " ")
	}

	var roles []string
	for _, role := range user.Roles {
		roles = append(roles, role.Name)
	}

	ret := TokenResponse{
		TokenType: "bearer",
		ExpiresIn: l.Client.TTL,
	}
	if l != nil {
		ret.CodeChallenge = l.CodeChallenge
		ret.CodeChallengeMethod = l.CodeChallengeMethod
	}

	accessToken, err := tokens.CreateToken(
		utils.Getenv("SSO_ISSUERKEY", "auth.denartcc.org"),
		l.Client.Name,
		fmt.Sprint(l.CID),
		l.Client.TTL,
		map[string]interface{}{
			"roles": roles,
		},
	)
	if err != nil {
		log4g.Category("controllers/token").Error("Error creating access token: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ret.AccessToken = string(accessToken)

	if contains(treq.Scope, "openid") {
		idtoken, err := tokens.CreateToken(
			utils.Getenv("SSO_ISSUERKEY", "auth.denartcc.org"),
			l.Client.Name,
			fmt.Sprint(l.CID),
			l.Client.TTL,
			map[string]interface{}{
				"name":        fmt.Sprintf("%s %s", user.FirstName, user.LastName),
				"given_name":  user.FirstName,
				"family_name": user.LastName,
				"email":       user.Email,
				"roles":       roles,
				"nonce":       l.Nonce,
			},
		)
		if err != nil {
			log4g.Category("controllers/token").Error("Error creating id token: %s", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		ret.IdToken = string(idtoken)
	}
	ret.RefreshToken, err = login.CreateRefreshToken(l, user)

	_, err = login.CleanupAuthorization(treq)
	if err != nil {
		log4g.Category("controllers/token").Error("Error cleaning up authorization: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ret)
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
