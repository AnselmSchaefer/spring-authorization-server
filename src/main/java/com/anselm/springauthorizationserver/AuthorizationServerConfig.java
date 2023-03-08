package com.anselm.springauthorizationserver;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration
                                        .OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client
                                            .InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client
                                                              .RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client
                                                    .RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
	
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		return http
				.formLogin(Customizer.withDefaults())
				.build();
	}
	
	@Bean
	public RegisteredClientRepository registeredClientRepository(
			PasswordEncoder passwordEncoder) {
		RegisteredClient registeredClient = 
				    // ID -> a random, unique identifier
					RegisteredClient.withId(UUID.randomUUID().toString())
				// analogous to a username, but instead of a user, it is a client
				.clientId("taco-admin-client")
				// analogous to a password for the client
				.clientSecret(passwordEncoder.encode("secret"))
				.clientAuthenticationMethod(
						ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				// the OAuth2 grant flow that this service will support
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				// one or more registered URLs that the authorization server can
				// redirect to after authorization has been granted (extra level of security)
				.redirectUri(
						"http://127.0.0.1:9090/login/oauth2/code/taco-admin-client")
				// one or more scopes that the client is allowed to ask for
				.scope("writeTacos")
				.scope("deleteTacos")
				// this scope will be necessary later when we use the authorization server as
				// single sign-on solution
				.scope(OidcScopes.OPENID)
				// lambda, allows us to customize the client settings
				.clientSettings(
			            ClientSettings.builder()
			            .requireAuthorizationConsent(true).build())
				.build();
		return new InMemoryRegisteredClientRepository(registeredClient);		
	}
	
	/*
	 * because the authorization server will produce JWT tokens, the token will
	 * will need to include a signature created using a JSON Web Key (JWK) as the
	 * signing key. The following beans are required to create the JWT.
	 */
	
	@Bean
	public ProviderSettings providerSettings() {
	    return ProviderSettings.builder()
	      .issuer("http://auth-server:9000")
	      .build();
	}

	  @Bean
	  public JWKSource<SecurityContext> jwkSource()
			  throws NoSuchAlgorithmException {
	    RSAKey rsaKey = generateRsa();
	    JWKSet jwkSet = new JWKSet(rsaKey);
	    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	  }

	  private static RSAKey generateRsa() throws NoSuchAlgorithmException {
	    KeyPair keyPair = generateRsaKey();
	    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
	    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
	    return new RSAKey.Builder(publicKey)
	        .privateKey(privateKey)
	        .keyID(UUID.randomUUID().toString())
	        .build();
	  }

	  private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
		  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		  keyPairGenerator.initialize(2048);
		  return keyPairGenerator.generateKeyPair();
	  }

	  @Bean
	  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
	    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	  }

}
