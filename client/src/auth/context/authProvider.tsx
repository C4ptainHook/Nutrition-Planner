import { useState, useEffect } from "react";
import type { ReactNode } from "react";
import { User } from "oidc-client-ts";
import { AuthContext } from "./authContext";
import authService from "../services/authService";
import type { AuthContextType } from "../types/auth.types";

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const initializeAuth = async () => {
      try {
        const loadedUser = await authService.getUser();
        setUser(loadedUser);
      } catch (error) {
        console.error("Auth Provider: Error loading user.", error);
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
    const userManager = authService.getUserManager();

    const onUserLoaded = (loadedUser: User) => {
      setUser(loadedUser);
      setIsLoading(false);
    };

    const onUserUnloaded = () => {
      setUser(null);
      setIsLoading(false);
    };

    const onAccessTokenExpiring = () => {
      console.log("Access token expiring - attempting silent renewal");
    };

    const onAccessTokenExpired = () => {
      console.log("Access token expired");
      setUser(null);
    };

    userManager.events.addUserLoaded(onUserLoaded);
    userManager.events.addUserUnloaded(onUserUnloaded);
    userManager.events.addAccessTokenExpiring(onAccessTokenExpiring);
    userManager.events.addAccessTokenExpired(onAccessTokenExpired);

    return () => {
      userManager.events.removeUserLoaded(onUserLoaded);
      userManager.events.removeUserUnloaded(onUserUnloaded);
      userManager.events.removeAccessTokenExpiring(onAccessTokenExpiring);
      userManager.events.removeAccessTokenExpired(onAccessTokenExpired);
    };
  }, []);

  const login = async (): Promise<void> => {
    setIsLoading(true);
    try {
      await authService.login();
    } catch (error) {
      console.error("Login error:", error);
      setIsLoading(false);
    }
  };

  const logout = async (): Promise<void> => {
    setIsLoading(true);
    try {
      await authService.logout();
    } catch (error) {
      console.error("Logout error:", error);
      setIsLoading(false);
    }
  };

  const getAccessToken = async (): Promise<string | null> => {
    return await authService.getAccessToken();
  };

  const authContextValue: AuthContextType = {
    user,
    isLoading,
    isAuthenticated: !!user && !user.expired,
    login,
    logout,
    getAccessToken,
  };

  if (isLoading) {
    return (
      <div className="auth-loading">
        <div>Loading Authentication...</div>
      </div>
    );
  }

  return (
    <AuthContext.Provider value={authContextValue}>
      {children}
    </AuthContext.Provider>
  );
};
