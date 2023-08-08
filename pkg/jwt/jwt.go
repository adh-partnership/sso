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

package jwt

import (
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWT struct {
	keyset *jwk.Set
}

func NewJWT(keyset string) (*JWT, error) {
	set, err := jwk.ParseString(keyset)
	if err != nil {
		return nil, err
	}

	return &JWT{
		keyset: &set,
	}, nil
}

func (j *JWT) GetPublicKeysOf() (*jwk.Key, error) {
	p, err := jwk.PublicKeyOf(j.keyset)
	if err != nil {
		return nil, err
	}

	return &p, nil
}
