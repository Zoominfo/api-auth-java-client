# Zoominfo API Auth Java Client

#### Auth flow using client id and private key
```
AuthClient authClient = new AuthClient("username", "clientId", "privateKey");
String accessToken = authClient.getAccessToken();
```

#### Auth flow using username and password
```
AuthClient authClient = new AuthClient("username", "password");
String accessToken = authClient.getAccessToken();
```


