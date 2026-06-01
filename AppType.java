package com.packetanalyzer.model;

/**
 * Application classification types.
 * Mirrors the C++ AppType enum.
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;

    /** Human-readable name for this app type. */
    public String displayName() {
        switch (this) {
            case TWITTER: return "Twitter/X";
            default:      return name().charAt(0) + name().substring(1).toLowerCase();
        }
    }

    /**
     * Map an SNI / domain string to an AppType.
     * Mirrors DPI::sniToAppType() in types.cpp.
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String s = sni.toLowerCase();

        // YouTube (check before Google because ytimg etc. are YouTube-specific)
        if (s.contains("youtube") || s.contains("ytimg") || s.contains("youtu.be")) return YOUTUBE;

        // Google
        if (s.contains("google") || s.contains("gstatic") ||
            s.contains("googleapis") || s.contains("ggpht") || s.contains("gvt1")) return GOOGLE;

        // Facebook / Meta
        if (s.contains("facebook") || s.contains("fbcdn") ||
            s.contains("fb.com") || s.contains("fbsbx") || s.contains("meta.com")) return FACEBOOK;

        // Instagram
        if (s.contains("instagram") || s.contains("cdninstagram")) return INSTAGRAM;

        // WhatsApp
        if (s.contains("whatsapp") || s.contains("wa.me")) return WHATSAPP;

        // Twitter / X
        if (s.contains("twitter") || s.contains("twimg") ||
            s.contains("x.com") || s.contains("t.co")) return TWITTER;

        // Netflix
        if (s.contains("netflix") || s.contains("nflxvideo") || s.contains("nflximg")) return NETFLIX;

        // Amazon / AWS
        if (s.contains("amazon") || s.contains("amazonaws") ||
            s.contains("cloudfront") || s.contains("aws")) return AMAZON;

        // Microsoft
        if (s.contains("microsoft") || s.contains("msn.com") || s.contains("office") ||
            s.contains("azure") || s.contains("live.com") ||
            s.contains("outlook") || s.contains("bing")) return MICROSOFT;

        // Apple
        if (s.contains("apple") || s.contains("icloud") ||
            s.contains("mzstatic") || s.contains("itunes")) return APPLE;

        // Telegram
        if (s.contains("telegram") || s.contains("t.me")) return TELEGRAM;

        // TikTok
        if (s.contains("tiktok") || s.contains("tiktokcdn") ||
            s.contains("musical.ly") || s.contains("bytedance")) return TIKTOK;

        // Spotify
        if (s.contains("spotify") || s.contains("scdn.co")) return SPOTIFY;

        // Zoom
        if (s.contains("zoom")) return ZOOM;

        // Discord
        if (s.contains("discord") || s.contains("discordapp")) return DISCORD;

        // GitHub
        if (s.contains("github") || s.contains("githubusercontent")) return GITHUB;

        // Cloudflare
        if (s.contains("cloudflare") || s.contains("cf-")) return CLOUDFLARE;

        return HTTPS; // SNI present but unrecognised → still TLS/HTTPS
    }
}
