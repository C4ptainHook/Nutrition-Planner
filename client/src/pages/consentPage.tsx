import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";

const ConsentPage = () => {
  const [returnUrl, setReturnUrl] = useState<string | null>(null);
  const location = useLocation();

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const url = params.get("returnUrl");
    setReturnUrl(url);
  }, [location]);

  if (!returnUrl) {
    return <div>Loading or invalid request...</div>;
  }

  const formActionUrl = "https://localhost:5050/connect/consent";

  return (
    <div>
      <h1>Consent Required</h1>
      <p>An application is requesting access to your account.</p>
      <hr />
      <form action={formActionUrl} method="post">
        <input type="hidden" name="returnUrl" value={returnUrl} />
        <button type="submit" name="decision" value="grant">
          Allow
        </button>
        <button type="submit" name="decision" value="deny">
          Deny
        </button>
      </form>
    </div>
  );
};

export default ConsentPage;
