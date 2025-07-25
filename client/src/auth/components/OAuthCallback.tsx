import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import authService from "../services/authService";

export const OAuthCallback = () => {
  const navigate = useNavigate();

  useEffect(() => {
    const handleCallback = async () => {
      try {
        await authService.handleCallback();
        const returnUrl = localStorage.getItem("returnUrl") || "/";
        localStorage.removeItem("returnUrl");
        navigate(returnUrl, { replace: true });
      } catch (error) {
        console.error("OAuth callback error:", error);
        navigate("/login?error=callback_failed", { replace: true });
      }
    };

    handleCallback();
  }, [navigate]);

  return (
    <div className="oauth-callback">
      <div>Processing authentication...</div>
    </div>
  );
};
