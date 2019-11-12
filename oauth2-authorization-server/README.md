### Simple authorization server with JWT token support

#### Test using curl

##### Request client authorization using authorization_code flow
````
curl -i -c cookies.txt "http://localhost:9191/as/oauth/authorize" -d "response_type=code&client_id=oauth2-client"
````
Result => Redirect to user authentication URL

##### Authenticate user
````
curl -i -b cookies.txt -c cookies.txt "http://localhost:9191/as/login" -d "username=oauth2-user&password=user-password"
````
Result => Redirect to authorization URL

#### Request authorization code
````
curl -i -b cookies.txt "http://localhost:9191/as/oauth/authorize" -d "redirect_uri=http://localhost:9291/login"
````
Result => Redirect to client redirect_uri, authentication code in query parameter

#### Request access token using authorization code + client credentials
````
curl -i -u "oauth2-client:client-password" "http://localhost:9191/as/oauth/token" -d "code=<authorization code>&grant_type=authorization_code&redirect_uri=http://localhost:9291/login"
````
Result => JWT-encoded access token

#### All in one
````
curl -i -c cookies.txt "http://localhost:9191/as/oauth/authorize" -d "response_type=code&client_id=oauth2-client"
curl -i -b cookies.txt -c cookies.txt "http://localhost:9191/as/login" -d "username=oauth2-user&password=user-password"
code=$(curl -si -b cookies.txt "http://localhost:9191/as/oauth/authorize" -d "redirect_uri=http://localhost:9292/login" | ggrep -oP 'Location:.*code=\K\w+')
curl -i -u "oauth2-client:client-password" "http://localhost:9191/as/oauth/token" -d "code=$code&grant_type=authorization_code&redirect_uri=http://localhost:9292/login"
````
