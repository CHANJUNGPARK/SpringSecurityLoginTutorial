package com.example.configuration;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private CustomizeAuthenticationSuccessHandler customizeAuthenticationSuccessHandler;

	@Autowired
	private DataSource dataSource;

	@Value("${spring.queries.users-query}")
	private String usersQuery;

	@Value("${spring.queries.roles-query}")
	private String rolesQuery;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().usersByUsernameQuery(usersQuery).authoritiesByUsernameQuery(rolesQuery)
				.dataSource(dataSource).passwordEncoder(bCryptPasswordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.formLogin()
				// 로그인 페이지
				.loginPage("/login")

				// 로그인 실패
				.failureUrl("/login?error=true")

				// 로그인 성공시 기본 페이지
				// .defaultSuccessUrl("/admin/home")

				// 로그인성공 이벤트
				.successHandler(customizeAuthenticationSuccessHandler)

				// 아이디 파라미터
				.usernameParameter("email")

				// 비밀번호 파라미터
				.passwordParameter("password");
		http.authorizeRequests()
				// 모든 사용자가 접근할 수 있는 여러 개의 URL 패턴지정.
				.antMatchers("/").permitAll().antMatchers("/login").permitAll().antMatchers("/registration").permitAll()

				// /admin/** 으로 시작하는 URL은 ADMIN ROLE 인 사용자에게만 제한.
				.antMatchers("/admin/**").hasAuthority("ADMIN").anyRequest().authenticated().and().csrf().disable();
		http.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/").and()
				.exceptionHandling().accessDeniedPage("/access-denied");

	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**");
	}
}