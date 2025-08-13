import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import styles from "./forgotPassword.module.scss";

const ForgotPasswordPage = () => {
  const [email, setEmail] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const response = await fetch("/api/v1/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      if (response.ok) {
        navigate("/reset-code");
      } else {
        setError("Recovery failed.");
      }
    } catch (error) {
      console.error("An error occurred during recovery", error);
      setError("An error occurred. See the console for details.");
    }
  };

  return (
    <div className={styles.pageContainer}>
      <form onSubmit={handleSubmit} className={styles.form}>
        <h2>Forgot password?</h2>
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
        <button type="submit" className={styles.submitButton}>
          Submit
        </button>
      </form>
      <p>
        <Link className={styles.loginLink} to="/login">
          Back to login
        </Link>
      </p>
    </div>
  );
};

export default ForgotPasswordPage;
