/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.openid.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

public class OpenIdAuthenticationFilter extends PostRequestAuthenticationProcessingFilter {

	public OpenIdAuthenticationFilter(ObjectMapper objectMapper) {
		super(objectMapper, new AntPathRequestMatcher("/login/openid", "POST"));
	}
	
	@Override
	protected AbstractAuthenticationToken authenticationToken(String username, String password) {
		return new OpenIdAuthenticationToken( username, password);
	}
	
}