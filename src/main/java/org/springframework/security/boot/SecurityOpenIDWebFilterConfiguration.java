package org.springframework.security.boot;

import javax.servlet.http.HttpServletRequest;

import org.openid4java.consumer.ConsumerException;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.ajax.AjaxAwareAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.ajax.AjaxAwareAuthenticationSuccessHandler;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.openid.OpenID4JavaConsumer;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.openid.OpenIDAuthenticationProvider;
import org.springframework.security.openid.OpenIDAuthenticationToken;
import org.springframework.security.openid.OpenIDConsumer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebFilterConfiguration"   // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityOpenIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityOpenIDProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityOpenIDWebFilterConfiguration implements ApplicationContextAware, EnvironmentAware {

	private ApplicationContext applicationContext;

	@Autowired
	private SecurityOpenIDProperties openidProperties;
	@Autowired
	private SecurityBizProperties bizProperties;

	@Bean
	protected BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationSuccessHandler successHandler() {
		
		// Ajax Login
		if(bizProperties.isLoginAjax()) {
			AjaxAwareAuthenticationSuccessHandler successHandler = new AjaxAwareAuthenticationSuccessHandler(null);
			return successHandler;
		}
		// Form Login
		else {
			SimpleUrlAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
			successHandler.setDefaultTargetUrl(bizProperties.getSuccessUrl());
			return successHandler;
		}
		
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationFailureHandler failureHandler() {
		// Ajax Login
		if(bizProperties.isLoginAjax()) {
			return new AjaxAwareAuthenticationFailureHandler(bizProperties.getFailureUrl());
		}
		// Form Login
		else {
			return new SimpleUrlAuthenticationFailureHandler(bizProperties.getFailureUrl());
		}
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}

	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}
 
    @Bean
	@ConditionalOnMissingBean
	public OpenIDConsumer openIDConsumer() throws ConsumerException {
		return new OpenID4JavaConsumer();
	}
    
    @Bean
	@ConditionalOnMissingBean
	public OpenIDAuthenticationFilter openIDAuthenticationFilter(AuthenticationFailureHandler failureHandler,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy,
			OpenIDConsumer openIDConsumer,
			Environment environment) throws Exception {
    	
    	OpenIDAuthenticationFilter authenticationFilter = new OpenIDAuthenticationFilter();
    	
    	authenticationFilter.setAllowSessionCreation(bizProperties.isAllowSessionCreation());
    	authenticationFilter.setApplicationEventPublisher(publisher);
    	authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
    	authenticationFilter.setAuthenticationFailureHandler(failureHandler);
    	authenticationFilter.setAuthenticationManager(authenticationManager);
    	authenticationFilter.setAuthenticationSuccessHandler(successHandler);
    	authenticationFilter.setClaimedIdentityFieldName(openidProperties.getClaimedIdentityFieldName());
    	authenticationFilter.setConsumer(openIDConsumer);
    	authenticationFilter.setContinueChainBeforeSuccessfulAuthentication(bizProperties.isContinueChainBeforeSuccessfulAuthentication());
    	authenticationFilter.setEnvironment(environment);
    	if (StringUtils.hasText(openidProperties.getFilterProcessesUrl())) {
    		authenticationFilter.setFilterProcessesUrl(openidProperties.getFilterProcessesUrl());
		}
		// authenticationFilter.setMessageSource(messageSource);
    	authenticationFilter.setRealmMapping(openidProperties.getRealmMapping());
    	authenticationFilter.setRememberMeServices(rememberMeServices);
    	authenticationFilter.setReturnToUrlParameters(openidProperties.getReturnToUrlParameters());
    	authenticationFilter.setSessionAuthenticationStrategy(sessionStrategy);
    	
        return authenticationFilter;
    }
    
    @Bean
   	@ConditionalOnMissingBean
   	public GrantedAuthoritiesMapper authoritiesMapper() {
   		return new NullAuthoritiesMapper();
   	}
    
	@Bean
	@ConditionalOnMissingBean
	public OpenIDAuthenticationProvider openIDAuthenticationProvider(
			AuthenticationUserDetailsService<OpenIDAuthenticationToken> userDetailsService,
			GrantedAuthoritiesMapper authoritiesMapper) {

		OpenIDAuthenticationProvider authenticationProvider = new OpenIDAuthenticationProvider();

		authenticationProvider.setAuthenticationUserDetailsService(userDetailsService);
		authenticationProvider.setAuthoritiesMapper(authoritiesMapper);

		return authenticationProvider;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		
		LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint(bizProperties.getLoginUrl());
		entryPoint.setForceHttps(bizProperties.isForceHttps());
		entryPoint.setUseForward(bizProperties.isUseForward());
		
		return entryPoint;
	}
	
	/**
	 * 系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
	 */
	@Bean
	@ConditionalOnMissingBean
	public LogoutFilter logoutFilter() {
		// 登录注销后的重定向地址：直接进入登录页面
		LogoutFilter logoutFilter = new LogoutFilter(bizProperties.getLoginUrl(), new SecurityContextLogoutHandler());
		logoutFilter.setFilterProcessesUrl(bizProperties.getLogoutUrlPatterns());
		return logoutFilter;
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

	@Override
	public void setEnvironment(Environment environment) {
		
	}

}
