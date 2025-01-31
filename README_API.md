## API for generating custom JWT (JSON Web Tokens) to use for authorization in Buerokratt applications

### POST jwt/custom-jwt-generate
Generates and registers a custom JWT from user login data

Content:
   
    Body: 
        JSON:   {
                "JWTName": "customJwtCookie",
                "expirationInMinutes": "{session_length}",
                "content": "{login}"
                },

	Parameters:
		session_length: session length in minutes, currently requested from Resql via Ruuter ("account/cs-get-session-length")
		login:			login data, currently requested from Resql ("/get-user-with-roles")

	Response:
		Success:
			HTTP 200 with new JWT that can be set as a cookie to verify authorization status of Buerokratt session
		Failure:
			HTTP 200 with empty response

### POST jwt/custom-jwt-verify
	Verifies that custom JWT {cookieName} set as a cookie in current session is previously registered and valid
	Fails if JWT is not registered, is blacklisted, is expired or is issued in the future.

	Content:
		Body:
			plain text: {cookieName}
		Cookie {cookieName}:
			JWT

	Response:
		Success:
			HTTP 200 
		Failure:
			HTTP 400

### POST jwt/custom-jwt-blacklist
	Deregisters custom JWT {cookieName} and registers it as blacklisted

	Content:
		Body:
			plain text: {cookieName}
		Cookie {cookieName}:
			JWT

	Response:
		HTTP 200 


### POST jwt/custom-jwt-extend
	Generates and registers a new custom JWT {cookieName} with extended expiration period from existing JWT
	Fails if JWT is not registered, is blacklisted or is already expired.

	Content:
		Body:
			plain text: {cookieName}
		Cookie {cookieName}:
			JWT

	Response:
		Failure: 
			HTTP 200 with empty payload
		Success:
			HTTP 200 with new JWT with expiration time calculated from current time

### POST jwt/custom-jwt-userinfo
	Returns generation and expiration timestamps of custom JWT {cookieName}
	Fails if JWT is not valid or not registered

	Content:
		Body:
			plain text: {cookieName}
		Cookie {cookieName}:
			JWT	

	Response:
		Failure:
			HTTP 200 with empty payload
		Success:
			HTTP 200 with a JSON map with JWT claims and extra keys "JWTCreated" and "JWTExpirationTimestamp" that contain timestamp of JWT creation and expiration respectively.


# API requests pertaining to TARA integration JWTs 

### GET jwt/verification-key
	Returns JWT public verification key

	Response:
		Success: 
			HTTP 200 with public key as plaintext
		Failure:
			System error

### POST jwt/verify
	Verifies JWT token validity

	Content:
		Body:
			plain text: {jwtTokenToCheck}

	Response:
		Success:
			HTTP 200
		Failure:
			HTTP 400

### POST jwt/userinfo
	Decodes JWT token without verifying its' expiration and responds with TARA userinfo
	Fails if cookie is not valid, not found or if userinfo cannot be parsed from JWT

	Content:
		Cookie: {TARA signature cookie name}

	Returns:
		Success:
			HTTP 200, JSON UserInfo object
		Failure:
			HTTP 400

### POST jwt/change-jwt-role
	Generates a new JWT with different user role from existing JWT; blacklists old JWT
	Fails if JWT does not specify user ID 


### POST jwt/blacklist
	Deregisters and blacklists specified JWT

	Content:
		Body:
			parameter: jwt={jwt}
			parameter: sessionId={sessionId}

	Returns:
		HTTP 200
