import type { ComponentType } from "react";
import { useAuth } from "../hooks/useAuth";

export function requireAuth<T extends object>(
  Component: ComponentType<T>
): ComponentType<T> {
  const AuthenticatedComponent = (props: T) => {
    const { isAuthenticated, isLoading, login } = useAuth();

    if (isLoading) {
      return <div>Loading...</div>;
    }

    if (!isAuthenticated) {
      return (
        <div className="auth-required">
          <h2>Authentication Required</h2>
          <p>You need to be logged in to access this feature.</p>
          <button onClick={login}>Sign In</button>
        </div>
      );
    }

    return <Component {...props} />;
  };

  AuthenticatedComponent.displayName = `requireAuth(${
    Component.displayName || Component.name
  })`;

  return AuthenticatedComponent;
}
