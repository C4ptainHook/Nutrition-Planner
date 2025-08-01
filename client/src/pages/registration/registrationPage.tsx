import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import styles from "./registration.module.scss";

const RegistrationPage = () => {
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [confirmPassword, setConfirmPassword] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const navigate = useNavigate();

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 6) {
      setError("Password must be at least 6 characters long.");
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch("/api/v1/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, confirmPassword }),
      });

      if (response.ok) {
        navigate("/login", {
          state: { message: "Registration successful! Please log in." },
        });
      } else {
        const errorData = await response.json();
        setError(
          errorData.message ||
            "Registration failed. The email may already be in use."
        );
      }
    } catch (err) {
      setError("An unexpected error occurred. Please try again later.");
      console.error("Registration failed:", err);
    } finally {
      setIsLoading(false);
    }
  };

  const inputErrorClass = error ? styles.inputError : "";

  return (
    <div className={styles.pageContainer}>
      <form onSubmit={handleSubmit} className={styles.form} noValidate>
        <h2>Create an Account</h2>
        <p>Train your Thany</p>
        <hr />

        {error && <div className={styles.errorMessage}>{error}</div>}

        <div className={styles.formGroup}>
          <label htmlFor="email" className={styles.label}>
            Email
          </label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={`${styles.input} ${inputErrorClass}`}
            required
            autoComplete="email"
          />
        </div>
        <div className={styles.formGroup}>
          <label htmlFor="password" className={styles.label}>
            Password
          </label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={`${styles.input} ${inputErrorClass}`}
            required
            autoComplete="new-password"
          />
        </div>
        <div className={styles.formGroup}>
          <label htmlFor="confirmPassword" className={styles.label}>
            Confirm Password
          </label>
          <input
            id="confirmPassword"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className={`${styles.input} ${inputErrorClass}`}
            required
            autoComplete="new-password"
          />
        </div>
        <button
          type="submit"
          className={styles.submitButton}
          disabled={isLoading}
        >
          {isLoading ? "Registering..." : "Register"}
        </button>
      </form>
      <p className={styles.registerLink}>
        Already have an account? <Link to="/login">Log In</Link>
      </p>
    </div>
  );
};

export default RegistrationPage;
