package us.xgraza.msa_auth;

/**
 * @author xgraza 7/11/26
 * The profile object for the account
 */
public final class MinecraftProfile
{
    private final String username, id;

    public MinecraftProfile(final String username, final String id)
    {
        this.username = username;
        this.id = id;
    }

    /**
     * @return the Minecraft account UUID (w/o dashes)
     */
    public String getId()
    {
        return id;
    }

    /**
     * @return the Minecraft account username
     */
    public String getUsername()
    {
        return username;
    }
}
