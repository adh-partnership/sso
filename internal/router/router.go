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

package router

import (
	"github.com/adh-partnership/api/pkg/logger"
	"github.com/adh-partnership/sso/v2/internal/oauth"
	"github.com/adh-partnership/sso/v2/internal/v1routes"
	"github.com/labstack/echo/v4"
)

var (
	log         = logger.Logger.WithField("component", "router")
	routeGroups map[string]func(e *echo.Group)
)

func init() {
	routeGroups = make(map[string]func(e *echo.Group))
	routeGroups["/oauth"] = oauth.Routes
	routeGroups["/v1"] = v1routes.Routes
}

func SetupRoutes(e *echo.Echo) {
	e.GET("/healthz", healthCheckHandler)
	e.GET("/ready", readyCheckHandler)

	for prefix, group := range routeGroups {
		log.Infof("Loading route prefix: %s", prefix)
		group(e.Group(prefix))
	}
}
