# msa-auth
An authentication library for authorizing your Minecraft accounts to your Minecraft clients.

---

# Branches
- [1.8](https://github.com/xgraza/msa-auth/tree/1.8)
- [1.20.4](https://github.com/xgraza/msa-auth/tree/1.20.4)

---

# Usage:

- Create an Azure account, make an application, set redirect url to "http://localhost:PORT/callback" using Single-page.
  - Obviously in the example above, please change the PORT value to the value you want to use.
- Copy down your application ID and replace `CLIENT_ID` in the example with your client ID.

### Creating the Authenticator instance
```java
final MSAAuthenticator msa = new MSAAuthenticator("CLIENT_ID", 5678);
```

### Email & Password authentication
```java
final MinecraftProfile profile = msa.login("microshit@hotmail.com", "youshallnotpass11");
```

### Logging in via Browser
```java
final String url = msa.browser((accessToken) -> {
  // You can do what you want with the access token, but we're going to login with it for example
  final MinecraftProfile profile = msa.login(accessToken);
  if (profile != null)
  {
    // Handle here
  }
});
// For example, we'll browse to this URL
Desktop.getDesktop().browse(new URI(url)); 
```

### Access tokens or refresh tokens
```java
// Or say you have a refresh token because your access token expired.
final String accessToken = msa.refresh(refreshToken);
final MinecraftProfile profile = msa.login(accessToken);
```

---
