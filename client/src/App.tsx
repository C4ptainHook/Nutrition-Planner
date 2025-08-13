import { Route, Routes } from "react-router";
import HomePage from "./pages/home/homePage";
import LoginPage from "./pages/login/loginPage";
import RegistrationPage from "./pages/registration/registrationPage";
import { OAuthCallback } from "./auth/components/oAuthCallback";
import ConsentPage from "./pages/consent/consentPage";
import AccessDeniedPage from "./pages/accessDenied/accessDeniedPage";
import ForgotPasswordPage from "./pages/forgotPassword/forgotPasswordPage";

function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegistrationPage />} />
      <Route path="/consent" element={<ConsentPage />} />
      <Route path="/oauth/callback" element={<OAuthCallback />} />
      <Route path="/access-denied" element={<AccessDeniedPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route
        path="/login-error"
        element={<h2>An error occurred during login.</h2>}
      />
    </Routes>
  );
}

export default App;
