import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import styles from "./consent.module.scss";

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
    <div className={styles.pageContainer}>
      <div className={styles.consentBox}>
        <h1 className={styles.title}>Consent Required</h1>
        <p className={styles.text}>
          An application is requesting access to your account.
        </p>
        <hr className={styles.divider} />
        <form action={formActionUrl} method="post">
          <input type="hidden" name="returnUrl" value={returnUrl} />
          <div className={styles.buttonGroup}>
            <button
              type="submit"
              name="decision"
              value="grant"
              className={styles.acceptButton}
            >
              Allow
            </button>
            <button
              type="submit"
              name="decision"
              value="deny"
              className={styles.denyButton}
            >
              Deny
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ConsentPage;
