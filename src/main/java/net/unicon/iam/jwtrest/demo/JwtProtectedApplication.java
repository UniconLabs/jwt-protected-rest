package net.unicon.iam.jwtrest.demo;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class JwtProtectedApplication {


	//Set as OS env variable CAS_JWT_SIGNING_SECRET
	@Value("${CAS_JWT_SIGNING_SECRET}")
	private String signingSecret;

	//Set as OS env variable CAS_JWT_ENCRYPTION_SECRET
	@Value("${CAS_JWT_ENCRYPTION_SECRET}")
	private String encryptionSecret;

	//To test JWT verification failure when keys don't match
	//private String signingSecret = "XZ4Iz7QkdRLPTJ6V1EYjXpgXbpXdZ3uixHOQ4AJVwyr6kkzqxmWCJhjEJiPaOGDqwsDHIGNP5AfEyGOGpOmSmQ";
	//private String encryptionSecret = "9OytxHyMtfEs09Hitzfixmb3JWoFqnKYGKr0wgjeYJ4";

	public static void main(String[] args) {
		SpringApplication.run(JwtProtectedApplication.class, args);
	}

	@Bean
	public FilterRegistrationBean<JwtValidationFilter> jwtValidationFilter() {
		return new FilterRegistrationBean<>(new JwtValidationFilter(signingSecret, encryptionSecret));
	}
}
