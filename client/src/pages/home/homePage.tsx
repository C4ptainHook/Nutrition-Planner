import { Link } from "react-router-dom";
import { useAuth } from "../../auth/hooks/useAuth";
import styles from "./home.module.scss";

const HomePage = () => {
  const { user, login, logout } = useAuth();

  return (
    <div className={styles.pageContainer}>
      <header className={styles.header}>
        <div className={styles.logo}>
          <Link to="/">Thany</Link>
        </div>
        <nav className={styles.actions}>
          {!user ? (
            <>
              <button onClick={login} className={styles.loginButton}>
                Log In
              </button>
              <Link to="/register" className={styles.signupButton}>
                Sign Up
              </Link>
            </>
          ) : (
            <button onClick={logout} className={styles.logoutButton}>
              Log Out
            </button>
          )}
        </nav>
      </header>

      <main className={styles.mainContent}>
        <h3 className={styles.welcomeMessage}>
          Welcome to the Thany Home Page
        </h3>
      </main>
    </div>
  );
};

export default HomePage;
