import React, { useState, useEffect } from "react";
import { useLocation, Link } from "react-router-dom";
import styles from "./login.module.scss";

const LoginPage = () => {
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [returnUrl, setReturnUrl] = useState<string>("/");
  const [error, setError] = useState<string | null>(null);
  const location = useLocation();

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const url = params.get("returnUrl");
    if (url) {
      setReturnUrl(url);
    }
  }, [location]);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const response = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (response.ok) {
        window.location.href = returnUrl;
      } else {
        setError("Login failed. Please check your credentials.");
      }
    } catch (error) {
      console.error("An error occurred during login", error);
      setError("An error occurred. See the console for details.");
    }
  };

  return (
    <div className={styles.pageContainer}>
      <form onSubmit={handleSubmit} className={styles.form}>
        <h2>Please Log In</h2>
        <p>You must log in to continue the process.</p>
        <hr />
        {error && <div className={styles.errorMessage}>{error}</div>}
        <div className={styles.formGroup}>
          <input
            type="email"
            value={email}
            autoComplete="email"
            placeholder="Email"
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setEmail(e.target.value)
            }
            className={styles.input + (error ? `${styles.inputError}` : "")}
            required
          />
        </div>
        <div className={styles.formGroup}>
          <input
            type="password"
            value={password}
            placeholder="Password"
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setPassword(e.target.value)
            }
            className={styles.input + (error ? `${styles.inputError}` : "")}
            required
          />
        </div>
        <button type="submit" className={styles.submitButton}>
          Submit
        </button>
      </form>
      <p>
        Don't have an account?{" "}
        <Link className={styles.registerLink} to="/register">
          Register now
        </Link>
      </p>
    </div>
  );
};

export default LoginPage;
