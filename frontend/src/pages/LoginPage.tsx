import { FormEvent, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useLogin, useRegistrationStatus } from "@/hooks/useAuth";
import { IntelFeedLogo } from "@/components/IntelFeedLogo";
import { AuthGraphBackground } from "@/components/AuthGraphBackground";
import styles from "./AuthPages.module.css";

export function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();
  const location = useLocation();
  const login = useLogin();
  // Signing in from the public view lands back on the page being read.
  const from = (location.state as { from?: string } | null)?.from;
  const { data: regStatus } = useRegistrationStatus();

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await login.mutateAsync({ username, password });
      navigate(from && from.startsWith("/") && !from.startsWith("//") ? from : "/");
    } catch {
      // error handled by mutation
    }
  };

  return (
    <div className={styles.container}>
      <AuthGraphBackground />
      <div className={styles.card}>
        <div className={styles.titleRow}>
          <IntelFeedLogo size={28} className={styles.titleLogo} />
          <h1 className={styles.titleText}>
            Intel<span className={styles.titleAccent}>Feed</span>
          </h1>
        </div>
        <p className={styles.subtitle}>Monitor · Correlate · Detect</p>
        <form onSubmit={handleSubmit} className={styles.form}>
          <div className={styles.field}>
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
            />
          </div>
          <div className={styles.field}>
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {login.isError && (
            <p className={styles.error}>Invalid username or password</p>
          )}
          <button type="submit" className={styles.button} disabled={login.isPending}>
            {login.isPending ? (
              "Signing in..."
            ) : (
              <>
                Sign In <span aria-hidden="true">→</span>
              </>
            )}
          </button>
        </form>
        {regStatus?.registration_enabled && (
          <p className={styles.link}>
            Don't have an account? <Link to="/register">Register</Link>
          </p>
        )}
        {regStatus?.public_read_only_enabled && (
          <p className={styles.link}>
            <Link to={from && from.startsWith("/") && !from.startsWith("//") ? from : "/"}>
              <span aria-hidden="true">←</span> Keep browsing read-only
            </Link>
          </p>
        )}
      </div>
    </div>
  );
}
