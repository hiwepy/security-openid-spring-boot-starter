package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.openid.OpenIDAuthenticationProvider;

@Configuration
@AutoConfigureBefore( name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebAutoConfiguration"  // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityOpenIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityOpenIDProperties.class })
@EnableWebSecurity
public class SecurityOpenIDWebAutoConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private SecurityOpenIDProperties openidProperties;
    @Autowired
    private OpenIDAuthenticationFilter openIDAuthenticationFilter;
    @Autowired 
    private OpenIDAuthenticationProvider openIDAuthenticationProvider;
    
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(openIDAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	
    	
    	
    	http.openidLogin()
//    	.attributeExchange(identifierPattern)
  //  	.authenticationDetailsSource(authenticationDetailsSource)
    	//.authenticationUserDetailsService(authenticationUserDetailsService)
    	.consumer(consumer);
    	
    	
    	http
        .exceptionHandling()
        //.authenticationEntryPoint(this.authenticationEntryPoint)
        
        .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        .and()
            .authorizeRequests()
                .antMatchers(StringUtils.hasText(openidProperties.getFilterProcessesUrl()) ? openidProperties.getFilterProcessesUrl() : "/login/openid" ).permitAll() // Login End-point
        .and()
            .authorizeRequests().anyRequest().authenticated() // Protected End-points
        .and()
            .addFilterBefore(openIDAuthenticationFilter, OpenIDAuthenticationFilter.class);
    	
    }

}
