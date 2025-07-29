import { Route, Routes } from "react-router";
import HomePage from "./pages/homePage";
import LoginPage from "./pages/login/loginPage";
import RegistrationPage from "./pages/registrationPage";
import { OAuthCallback } from "./auth/components/OAuthCallback";
import ConsentPage from "./pages/consentPage";
import AccessDeniedPage from "./pages/accessDenied/accessDeniedPage";

function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegistrationPage />} />
      <Route path="/consent" element={<ConsentPage />} />
      <Route path="/oauth/callback" element={<OAuthCallback />} />
      <Route path="/access-denied" element={<AccessDeniedPage />} />
      <Route
        path="/login-error"
        element={<h2>An error occurred during login.</h2>}
      />
    </Routes>
  );
}

export default App;
