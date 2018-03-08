package org.springframework.security.boot;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = SecurityOpenIDProperties.PREFIX)
public class SecurityOpenIDProperties {

	public static final String PREFIX = "spring.security.openid";
	public static final String DEFAULT_CLAIMED_IDENTITY_FIELD = "openid_identifier";

	/**
	 * Enable Security OpenID.
	 */
	private boolean enabled = false;

	/** The URL that determines if authentication is required */
	private String filterProcessesUrl;
	
	/**
	 * The name of the request parameter containing the OpenID identity, as
	 * submitted from the initial login form. Defaults to "openid_identifier"
	 */
	private String claimedIdentityFieldName = DEFAULT_CLAIMED_IDENTITY_FIELD;

	/**
	 * Maps the <tt>return_to url</tt> to a realm, for example:
	 *
	 * <pre>
	 * http://www.example.com/login/openid -&gt; http://www.example.com/realm
	 * </pre>
	 *
	 * If no mapping is provided then the returnToUrl will be parsed to extract the
	 * protocol, hostname and port followed by a trailing slash. This means that
	 * <tt>http://www.example.com/login/openid</tt> will automatically become
	 * <tt>http://www.example.com:80/</tt>
	 */
	private Map<String, String> realmMapping = Collections.emptyMap();

	/**
	 * Specifies any extra parameters submitted along with the identity field which
	 * should be appended to the return_to URL which is assembled by
	 * buildReturnToUrl.
	 * <p>
	 * If not set, it will default to the parameter name used by the
	 * RememberMeServices obtained from the parent class (if one is set).
	 */
	private Set<String> returnToUrlParameters = Collections.emptySet();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
	public String getFilterProcessesUrl() {
		return filterProcessesUrl;
	}

	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.filterProcessesUrl = filterProcessesUrl;
	}

	public String getClaimedIdentityFieldName() {
		return claimedIdentityFieldName;
	}

	public void setClaimedIdentityFieldName(String claimedIdentityFieldName) {
		this.claimedIdentityFieldName = claimedIdentityFieldName;
	}

	public Map<String, String> getRealmMapping() {
		return realmMapping;
	}

	public void setRealmMapping(Map<String, String> realmMapping) {
		this.realmMapping = realmMapping;
	}

	public Set<String> getReturnToUrlParameters() {
		return returnToUrlParameters;
	}

	public void setReturnToUrlParameters(Set<String> returnToUrlParameters) {
		this.returnToUrlParameters = returnToUrlParameters;
	}
	
}
