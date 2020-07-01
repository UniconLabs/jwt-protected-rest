package net.unicon.iam.jwtrest.demo;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Map;

import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;

public class JwtValidationFilter extends OncePerRequestFilter {

    private final String HEADER = "Authorization";

    private final String PREFIX = "Bearer ";

    //Set as OS env variable CAS_JWT_SIGNING_SECRET
    @Value("${CAS_JWT_SIGNING_SECRET}")
    private String signingSecret;

    //Set as OS env variable CAS_JWT_ENCRYPTION_SECRET
    @Value("${CAS_JWT_ENCRYPTION_SECRET}")
    private String encryptionSecret;

    public JwtValidationFilter(String signingSecret, String encryptionSecret) {
        this.signingSecret = signingSecret;
        this.encryptionSecret = encryptionSecret;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        var jwtClaims = retrieveValidJwtClaims(request);
        if (jwtClaims == null) {
            response.setStatus(SC_FORBIDDEN);
            response.sendError(SC_FORBIDDEN);
        }
        filterChain.doFilter(request, response);
    }

    private JwtClaims retrieveValidJwtClaims(HttpServletRequest request) {
        String header = request.getHeader(HEADER);
        if (header == null || !header.startsWith(PREFIX)) {
            return null;
        }
        String encryptedJwt = header.replace(PREFIX, "");
        return decryptJwt(encryptedJwt);
    }

    private JwtClaims decryptJwt(String jwt) {
        try {
            //First Signature verification
            final Key signingKey = new AesKey(signingSecret.getBytes(StandardCharsets.UTF_8));
            final JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(jwt);
            jws.setKey(signingKey);
            if (!jws.verifySignature()) {
                throw new JoseException("JWT verification failed");
            }

            //Then get encrypted payload
            final byte[] decodedBytes = Base64.getDecoder().decode(jws.getEncodedPayload().getBytes(StandardCharsets.UTF_8));
            final String decodedPayload = new String(decodedBytes, StandardCharsets.UTF_8);

            //Finally decrypt into JWT claims
            final JsonWebEncryption jwe = new JsonWebEncryption();
            final JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(Map.of("kty", "oct", "k", encryptionSecret));
            jwe.setCompactSerialization(decodedPayload);
            jwe.setKey(new AesKey(jsonWebKey.getKey().getEncoded()));
            return JwtClaims.parse(jwe.getPayload());
        } catch (JoseException | InvalidJwtException e) {
            e.printStackTrace();
            return null;
        }
    }
}
