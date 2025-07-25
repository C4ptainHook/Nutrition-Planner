import { UserManager } from "oidc-client-ts";
import type { UserManagerSettings } from "oidc-client-ts";
import type { AuthConfig } from "../types/auth.types";

const oidcConfig: AuthConfig = {
  authority: "https://localhost:5050",
  clientId: "react-client",
  redirectUri: "http://localhost:5173/oauth/callback",
  postLogoutRedirectUri: "http://localhost:5173/",
  scope: "openid profile email roles",
  responseType: "code",
};

const oidcSettings: UserManagerSettings = {
  authority: oidcConfig.authority,
  client_id: oidcConfig.clientId,
  redirect_uri: oidcConfig.redirectUri,
  response_type: oidcConfig.responseType,
  scope: oidcConfig.scope,
  post_logout_redirect_uri: oidcConfig.postLogoutRedirectUri,
  loadUserInfo: true,
  automaticSilentRenew: true,
  silent_redirect_uri: `${window.location.origin}/silent-callback`,
  accessTokenExpiringNotificationTimeInSeconds: 60,
  silentRequestTimeoutInSeconds: 10,
};

class AuthService {
  private userManager: UserManager;

  constructor() {
    this.userManager = new UserManager(oidcSettings);
    this.setupEventHandlers();
  }

  private setupEventHandlers() {
    this.userManager.events.addUserLoaded((user) => {
      console.log("User loaded:", user);
    });

    this.userManager.events.addUserUnloaded(() => {
      console.log("User unloaded");
    });

    this.userManager.events.addAccessTokenExpiring(() => {
      console.log("Access token expiring");
    });

    this.userManager.events.addAccessTokenExpired(() => {
      console.log("Access token expired");
    });

    this.userManager.events.addSilentRenewError((error) => {
      console.error("Silent renew error:", error);
    });
  }

  public getUserManager(): UserManager {
    return this.userManager;
  }

  public async getUser() {
    return await this.userManager.getUser();
  }

  public async login(): Promise<void> {
    await this.userManager.signinRedirect();
  }

  public async logout(): Promise<void> {
    await this.userManager.signoutRedirect();
  }

  public async handleCallback(): Promise<void> {
    await this.userManager.signinRedirectCallback();
  }

  public async getAccessToken(): Promise<string | null> {
    const user = await this.getUser();
    return user?.access_token || null;
  }

  public async isAuthenticated(): Promise<boolean> {
    const user = await this.getUser();
    return !!user && !user.expired;
  }
}

const authService = new AuthService();
export default authService;
