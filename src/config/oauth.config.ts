export interface OAuthProviderSettings {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authEndpoint: string;
  tokenEndpoint: string;
  userInfoEndpoint: string;
}

export interface GitHubOAuthSettings extends OAuthProviderSettings {
  userEmailsEndpoint: string;
}

export interface OAuthConfig {
  google: OAuthProviderSettings;
  github: GitHubOAuthSettings;
}

export function loadOAuthConfig(): OAuthConfig {
  return {
    google: {
      clientId: process.env.AUTH_OAUTH_GOOGLE_CLIENT_ID || 'mock_google_client_id_001',
      clientSecret: process.env.AUTH_OAUTH_GOOGLE_CLIENT_SECRET || 'mock_google_client_secret_001',
      redirectUri: process.env.AUTH_OAUTH_GOOGLE_REDIRECT_URI || 'http://localhost:3000/api/v1/auth/oauth/google/callback',
      authEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenEndpoint: 'https://oauth2.googleapis.com/token',
      userInfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
    },
    github: {
      clientId: process.env.AUTH_OAUTH_GITHUB_CLIENT_ID || 'mock_github_client_id_001',
      clientSecret: process.env.AUTH_OAUTH_GITHUB_CLIENT_SECRET || 'mock_github_client_secret_001',
      redirectUri: process.env.AUTH_OAUTH_GITHUB_REDIRECT_URI || 'http://localhost:3000/api/v1/auth/oauth/github/callback',
      authEndpoint: 'https://github.com/login/oauth/authorize',
      tokenEndpoint: 'https://github.com/login/oauth/access_token',
      userInfoEndpoint: 'https://api.github.com/user',
      userEmailsEndpoint: 'https://api.github.com/user/emails',
    },
  };
}
