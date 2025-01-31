package ee.eesti.authentication.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.Map;

/**
 * Data transfer object to hold information related to requesting a CustomJwtToken
 * @see ee.eesti.authentication.controller.CustomJwtController
 * @see ee.eesti.authentication.repository.entity.CustomJwtTokenInfo
 */
@Data
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomJwtTokenRequest {

    private Map<String, Object> content;

    @Min(1L)
    private int expirationInMinutes;

    @JsonProperty("JWTName")
    @NotEmpty
    @NotNull
    private String jwtName;
}
