import React, { useState, useEffect } from "react";
import { useLocation, Link } from "react-router-dom";

const LoginPage = () => {
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [returnUrl, setReturnUrl] = useState<string>("/");
  const location = useLocation();

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const url = params.get("ReturnUrl");
    if (url) {
      console.log("Redirecting back to:", url);
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
        alert("Login failed. Please check your credentials.");
      }
    } catch (error) {
      console.error("An error occurred during login", error);
      alert("An error occurred. See the console for details.");
    }
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <h2>Please Log In</h2>
        <p>You must log in to continue the process.</p>
        <hr />
        <div>
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setEmail(e.target.value)
            }
            required
          />
        </div>
        <div>
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setPassword(e.target.value)
            }
            required
          />
        </div>
        <button type="submit">Submit</button>
      </form>
      <p>
        Don't have an account? <Link to="/register">Register now</Link>
      </p>
    </div>
  );
};

export default LoginPage;
