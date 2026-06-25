## API for generating custom JWT (JSON Web Tokens) to use for authorization in Buerokratt applications

### POST jwt/custom-jwt-generate
Generates and registers a custom JWT from user login data

Content:
   
    Body: 
```json
      {
        "JWTName": "customJwtCookie",
        "expirationInMinutes": "{session_length}",
        "content": "{login}"
      }
```
Parameters:

    session_length: session length in minutes, currently requested from Resql via Ruuter ("account/cs-get-session-length")

    login:			login data, currently requested from Resql ("/get-user-with-roles")

Example:

```bash
curl -X POST RESQL/get-user-with-roles -H "Content-Type: application/json" -d '{"login":"EE30303039914"}'
curl -X POST TIM/jwt/custom-jwt-generate -d '{"JWTName": "customJwtCookie", "expirationInMinutes": 1280, "content" : {"login":"EE30303039914","firstName":"DELETE","lastName":"ME","idCode":"EE30303039914","displayName":"deleteMe","csaTitle":"","csaEmail":"delete@m.ee","authorities":["ROLE_ADMINISTRATOR"]} }' -H "Content-type: application/json"
```

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

Example:

```bash
curl  -X POST TIM/jwt/custom-jwt-verify -d 'customJwtCookie' \
-H 'Cookie: JWTToken:<token>; customJwtCookie:<token>'
```

### POST jwt/custom-jwt-blacklist
	Deregisters custom JWT {cookieName} and registers it as blacklisted

	Content:
		Body:
			plain text: {cookieName}
		Cookie {cookieName}:
			JWT

	Response:
		HTTP 200 



Example:

```bash
curl  -X POST TIM/jwt/custom-jwt-blacklist -d 'customJwtCookie' \
-H 'Cookie: JWTToken:<token>; customJwtCookie:<token>'
```

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

Example:

```bash
curl  -X POST TIM/jwt/custom-jwt-extend -d 'customJwtCookie' \
-H 'Cookie: JWTToken:<token>; customJwtCookie:<token>'
```

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
Example:

```bash
curl  -X POST TIM/jwt/custom-jwt-userinfo -d 'customJwtCookie' \
-H 'Cookie: JWTToken:<token>; customJwtCookie:<token>'
```


# API requests pertaining to TARA integration JWTs 

### GET jwt/verificationey
	Returns JWT public verification key

	Response:
		Success: 
			HTTP 200 with public key as plaintext
		Failure:
			System error

```bash
curl  -X GET TIM/jwt/verificationey
```

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

```bash
curl -v -X POST TIM/jwt/verify -d '<token>'
```

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

```bash
curl -v -X GET TIM/jwt/userinfo -d 'JWTTOKEN' -H 'cookie: JWTTOKEN=<token>'
```

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

```bash
curl -v -X POST "TIM/jwt/blacklist?jwt=JWTTOKEN" -H 'cookie: JWTTOKEN=<token>'
```