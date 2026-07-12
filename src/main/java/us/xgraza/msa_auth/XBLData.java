package us.xgraza.msa_auth;

/**
 * @author xgraza 7/11/2026
 * @apiNote Used when fetching Xbox Live account information (such as Token & uhs)
 */
final class XBLData
{
    private String token, userHash;

    public String getToken()
    {
        return token;
    }

    public void setToken(String token)
    {
        this.token = token;
    }

    public String getUserHash()
    {
        return userHash;
    }

    public void setUserHash(String userHash)
    {
        this.userHash = userHash;
    }
}
