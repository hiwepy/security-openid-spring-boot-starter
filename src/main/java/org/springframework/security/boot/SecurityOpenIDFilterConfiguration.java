package org.springframework.security.boot;

import org.openid4java.consumer.ConsumerManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.openid.authentication.OpenIDAuthenticationFailureHandler;
import org.springframework.security.boot.openid.authentication.OpenIDAuthenticationSuccessHandler;
import org.springframework.security.boot.openid.userdetails.OpenIDAuthcUserDetailsService;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.openid.OpenIDAuthenticationProvider;
import org.springframework.security.openid.OpenIDConsumer;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebFilterConfiguration"   // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityOpenIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityOpenIDProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityOpenIDFilterConfiguration implements ApplicationEventPublisherAware, EnvironmentAware {


	private ApplicationEventPublisher eventPublisher;
	private Environment environment;
	
	@Autowired
	private SecurityOpenIDProperties openidProperties;
	
	@Autowired
	private OpenIDAuthenticationSuccessHandler successHandler;
	@Autowired
	private OpenIDAuthenticationFailureHandler failureHandler;
	@Autowired
	private OpenIDConsumer openIDConsumer;
	@Autowired
	private AuthenticationManager authenticationManager; 
	@Autowired
	private RememberMeServices rememberMeServices;
	@Autowired
	private SessionAuthenticationStrategy sessionStrategy;
	
    @Bean
	public OpenIDAuthenticationFilter openIDAuthenticationFilter() throws Exception {
    	
    	OpenIDAuthenticationFilter authcFilter = new OpenIDAuthenticationFilter();
    	
    	authcFilter.setAllowSessionCreation(openidProperties.getAuthc().isAllowSessionCreation());
    	authcFilter.setApplicationEventPublisher(eventPublisher);
    	//authcFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
    	authcFilter.setAuthenticationFailureHandler(failureHandler);
    	authcFilter.setAuthenticationManager(authenticationManager);
    	authcFilter.setAuthenticationSuccessHandler(successHandler);
    	authcFilter.setClaimedIdentityFieldName(openidProperties.getAuthc().getClaimedIdentityFieldName());
    	authcFilter.setConsumer(openIDConsumer);
    	authcFilter.setContinueChainBeforeSuccessfulAuthentication(openidProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
    	authcFilter.setEnvironment(environment);
    	if (StringUtils.hasText(openidProperties.getAuthc().getFilterProcessesUrl())) {
    		authcFilter.setFilterProcessesUrl(openidProperties.getAuthc().getFilterProcessesUrl());
		}
		// authenticationFilter.setMessageSource(messageSource);
    	authcFilter.setRealmMapping(openidProperties.getAuthc().getRealmMapping());
    	authcFilter.setRememberMeServices(rememberMeServices);
    	authcFilter.setReturnToUrlParameters(openidProperties.getAuthc().getReturnToUrlParameters());
    	authcFilter.setSessionAuthenticationStrategy(sessionStrategy);
    	
        return authcFilter;
    }
    
	@Bean
	public OpenIDAuthenticationProvider openIDAuthenticationProvider(
			OpenIDAuthcUserDetailsService openIDAuthcUserDetailsService, 
			GrantedAuthoritiesMapper authoritiesMapper) {

		OpenIDAuthenticationProvider authcProvider = new OpenIDAuthenticationProvider();

		authcProvider.setAuthenticationUserDetailsService(openIDAuthcUserDetailsService);
		authcProvider.setAuthoritiesMapper(authoritiesMapper);

		return authcProvider;
	}
	
	@Configuration
	@EnableConfigurationProperties({ SecurityOpenIDProperties.class, SecurityBizProperties.class })
	static class OpenIDWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		private final ConsumerManager consumerManager;
		private final OpenIDAttribute attribute;
	    private final OpenIDAuthenticationFilter openIDAuthenticationFilter;
	    private final OpenIDAuthenticationProvider openIDAuthenticationProvider;
	    private final OpenIDAuthenticationSuccessHandler successHandler;
	    private final OpenIDAuthenticationFailureHandler failureHandler;
		private final OpenIDAuthcUserDetailsService openIDAuthcUserDetailsService;
		private final OpenIDConsumer consumer;
		private final SecurityOpenIDProperties properties;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	
		public OpenIDWebSecurityConfigurerAdapter(
				SecurityOpenIDProperties properties,
				ObjectProvider<OpenIDAttribute> attributeProvider,
				ObjectProvider<OpenIDAuthenticationFilter> openIDAuthenticationFilterProvider,
				ObjectProvider<OpenIDAuthenticationProvider> openIDAuthenticationProvider,
				ObjectProvider<OpenIDAuthcUserDetailsService> openIDAuthcUserDetailsService, 
				ObjectProvider<OpenIDConsumer> consumerProvider,
				ObjectProvider<ConsumerManager> consumerManagerProvider,
				ObjectProvider<OpenIDAuthenticationSuccessHandler> successHandlerProvider,
				ObjectProvider<OpenIDAuthenticationFailureHandler> failureHandlerProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
			this.attribute = attributeProvider.getIfAvailable();
			this.properties = properties;
			this.openIDAuthenticationFilter = openIDAuthenticationFilterProvider.getIfAvailable();
			this.openIDAuthenticationProvider = openIDAuthenticationProvider.getIfAvailable();
			this.openIDAuthcUserDetailsService = openIDAuthcUserDetailsService.getIfAvailable();
			this.consumer = consumerProvider.getIfAvailable();
			this.consumerManager = consumerManagerProvider.getIfAvailable();
			this.successHandler = successHandlerProvider.getIfAvailable();
			this.failureHandler = failureHandlerProvider.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}

	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) {
	        auth.authenticationProvider(openIDAuthenticationProvider);
	    }
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			
			http.openidLogin()
				.attributeExchange(properties.getAuthc().getIdentifierPattern())
				.attribute(attribute)
				.and()
				.authenticationUserDetailsService(this.openIDAuthcUserDetailsService)
				.consumer(this.consumer)
				.consumerManager(this.consumerManager)
				.defaultSuccessUrl(properties.getAuthc().getSuccessUrl())
				.failureHandler(this.failureHandler)
				.failureUrl(properties.getAuthc().getFailureUrl())
				.loginProcessingUrl(properties.getAuthc().getLoginUrl())
				.successHandler(this.successHandler)
				.and()
				.sessionManagement()
				.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
	            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	            .and()
	            .addFilterBefore(openIDAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
			
		}

	}
	
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

	@Override
	public void setEnvironment(Environment environment) {
		this.environment = environment;
	}
	
}
