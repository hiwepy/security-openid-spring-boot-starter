package org.springframework.security.boot;

import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.openid.userdetails.OpenIDAuthcUserDetailsService;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.openid.AxFetchListFactory;
import org.springframework.security.openid.NullAxFetchListFactory;
import org.springframework.security.openid.OpenID4JavaConsumer;
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
public class SecurityOpenIDFilterConfiguration implements EnvironmentAware {

	private Environment environment;
    
	@Bean
	@ConditionalOnMissingBean
	public ConsumerManager consumerManager() {
		return new ConsumerManager();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public AxFetchListFactory attributesToFetchFactory() {
		return new  NullAxFetchListFactory();
	}
	
    @Bean
	@ConditionalOnMissingBean
	public OpenIDConsumer openIDConsumer(ConsumerManager consumerManager,
			AxFetchListFactory attributesToFetchFactory) throws ConsumerException {
		return new OpenID4JavaConsumer(consumerManager, attributesToFetchFactory);
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
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 7)
	static class OpenIDWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		private SecurityBizProperties bizProperties;
		
		private OpenIDConsumer openIDConsumer;
		private AuthenticationManager authenticationManager; 
		private RememberMeServices rememberMeServices;
		private SessionAuthenticationStrategy sessionStrategy;
		
		private final ConsumerManager consumerManager;
		private final OpenIDAttribute attribute;
	    private final OpenIDAuthenticationFilter openIDAuthenticationFilter;
	    private final OpenIDAuthenticationProvider openIDAuthenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
		private final OpenIDAuthcUserDetailsService openIDAuthcUserDetailsService;
		private final OpenIDConsumer consumer;
		private final SecurityOpenIDAuthcProperties authcProperties;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
	
		public OpenIDWebSecurityConfigurerAdapter(
				SecurityOpenIDAuthcProperties authcProperties,
				
				ObjectProvider<OpenIDAttribute> attributeProvider,
				ObjectProvider<OpenIDAuthenticationFilter> openIDAuthenticationFilterProvider,
				ObjectProvider<OpenIDAuthenticationProvider> openIDAuthenticationProvider,
				ObjectProvider<OpenIDAuthcUserDetailsService> openIDAuthcUserDetailsService, 
				ObjectProvider<OpenIDConsumer> consumerProvider,
				ObjectProvider<ConsumerManager> consumerManagerProvider,
				@Qualifier("jwtAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				@Qualifier("jwtAuthenticationFailureHandler") ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider) {
			this.attribute = attributeProvider.getIfAvailable();
			this.authcProperties = authcProperties;
			this.openIDAuthenticationFilter = openIDAuthenticationFilterProvider.getIfAvailable();
			this.openIDAuthenticationProvider = openIDAuthenticationProvider.getIfAvailable();
			this.openIDAuthcUserDetailsService = openIDAuthcUserDetailsService.getIfAvailable();
			this.consumer = consumerProvider.getIfAvailable();
			this.consumerManager = consumerManagerProvider.getIfAvailable();
			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}

		public OpenIDAuthenticationFilter authenticationProcessingFilter() throws Exception {
	    	
	    	OpenIDAuthenticationFilter authenticationFilter = new OpenIDAuthenticationFilter();
	    	/*
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(authcProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getClaimedIdentityFieldName()).to(authenticationFilter::setClaimedIdentityFieldName);
			map.from(authcProperties.getRealmMapping()).to(authenticationFilter::setRealmMapping);
			map.from(openIDConsumer).to(authenticationFilter::setConsumer);
			map.from(authcProperties.getFilterProcessesUrl()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.getReturnToUrlParameters()).to(authenticationFilter::setReturnToUrlParameters);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
	    	
	        return authenticationFilter;
	    }

	    @Override
		public void configure(AuthenticationManagerBuilder auth) {
	        auth.authenticationProvider(openIDAuthenticationProvider);
	    }
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			
			http.openidLogin()
				.attributeExchange(authcProperties.getIdentifierPattern())
				.attribute(attribute)
				.and()
				.authenticationUserDetailsService(this.openIDAuthcUserDetailsService)
				.consumer(this.consumer)
				.consumerManager(this.consumerManager)
				.defaultSuccessUrl(authcProperties.getSuccessUrl())
				.failureHandler(this.authenticationFailureHandler)
				.failureUrl(authcProperties.getFailureUrl())
				.loginProcessingUrl(authcProperties.getLoginUrl())
				.successHandler(this.authenticationSuccessHandler)
				.and()
				.sessionManagement()
				.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
	            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	            .and()
	            .addFilterBefore(openIDAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
			
		}

	}

	@Override
	public void setEnvironment(Environment environment) {
		this.environment = environment;
	}
	
}
