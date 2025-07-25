import { useAuth } from "../auth/hooks/useAuth";

const HomePage = () => {
  const { user, login, logout } = useAuth();

  return (
    <div>
      <h3>Welcome to the Thany Home Page</h3>
      {!user ? (
        <button onClick={login}>Log In</button>
      ) : (
        <button onClick={logout}>Log Out</button>
      )}
    </div>
  );
};

export default HomePage;
