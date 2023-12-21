package ra.jwt;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ra.sercurity.CustomUserDetails;

import java.util.Date;

@Component
@Slf4j
public class JwtTokenProvider {
    @Value("${ra.jwt.secret}")
    private String JWT_SECRET;
    @Value("${ra.jwt.experation}")
    private int JWT_EXPERATION;

    //Tao JWT tu thong tin cua User
    public String generateToken(CustomUserDetails customUserDetails) {
        Date now = new Date();
        Date dateExpired = new Date(now.getTime() + JWT_EXPERATION);
        //Tao chuoi JWT tu userName
        return Jwts.builder().setSubject(customUserDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(dateExpired)
                .signWith(SignatureAlgorithm.HS512, JWT_SECRET).compact();
    }

    //lay thong tin User tu JWT
    public String getUserNameFromJWT(String token) {
        Claims claims = Jwts.parser().setSigningKey(JWT_SECRET)
                .parseClaimsJws(token).getBody();
        return claims.getSubject();
    }

    //Validate thong tin cua JWT
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(JWT_SECRET)
                    .parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty");
        }
        return false;
    }
}
