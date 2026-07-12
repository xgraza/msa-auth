package us.xgraza.msa_auth;

/**
 * @author xgraza 7/11/2026
 */
final class OAuthResult
{
    public final String sfttTag, postUrl, cookie;

    public OAuthResult(String sfttTag, String postUrl, String cookie)
    {
        this.sfttTag = sfttTag;
        this.postUrl = postUrl;
        this.cookie = cookie;
    }
}
