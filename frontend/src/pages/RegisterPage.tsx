import { FormEvent, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useRegister, useRegistrationStatus } from "@/hooks/useAuth";
import { IntelFeedLogo } from "@/components/IntelFeedLogo";
import { AuthGraphBackground } from "@/components/AuthGraphBackground";
import styles from "./AuthPages.module.css";

export function RegisterPage() {
  const [searchParams] = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [inviteCode, setInviteCode] = useState(searchParams.get("invite") ?? "");
  const navigate = useNavigate();
  const register = useRegister();
  const { data: regStatus } = useRegistrationStatus();
  const inviteRequired = regStatus?.invite_code_required ?? false;
  const hasInviteFromUrl = Boolean(searchParams.get("invite"));

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await register.mutateAsync({
        username,
        password,
        invite_code: inviteCode || undefined,
      });
      navigate("/");
    } catch {
      // error handled by mutation
    }
  };

  const errorMessage = register.error
    ? (register.error as { response?: { data?: { message?: string } } })?.response?.data?.message
      || "Registration failed"
    : null;

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
        <p className={styles.subtitle}>Create your account</p>
        <form onSubmit={handleSubmit} className={styles.form}>
          {inviteRequired && !hasInviteFromUrl && (
            <div className={styles.field}>
              <label htmlFor="inviteCode">Invite Code</label>
              <input
                id="inviteCode"
                type="password"
                value={inviteCode}
                onChange={(e) => setInviteCode(e.target.value)}
                required
                autoFocus
                autoComplete="off"
              />
            </div>
          )}
          <div className={styles.field}>
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus={!inviteRequired}
              minLength={3}
              maxLength={30}
              pattern="[a-zA-Z0-9_]{3,30}"
              title="3-30 characters, letters, numbers, and underscores"
            />
          </div>
          <div className={styles.field}>
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={6}
            />
          </div>
          {errorMessage && (
            <p className={styles.error}>{errorMessage}</p>
          )}
          <button type="submit" className={styles.button} disabled={register.isPending}>
            {register.isPending ? (
              "Creating account..."
            ) : (
              <>
                Create Account <span aria-hidden="true">→</span>
              </>
            )}
          </button>
        </form>
        <p className={styles.link}>
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
