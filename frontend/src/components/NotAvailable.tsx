import { Link, useLocation } from "react-router-dom";
import styles from "./NotAvailable.module.css";

/** What a visitor sees on a page that isn't part of the public read-only view. */
export function NotAvailable() {
  const location = useLocation();
  return (
    <div className={styles.wrap}>
      <div>
        <h2 className={styles.title}>Not available</h2>
        <p className={styles.text}>This page is for signed-in users.</p>
        <Link to="/login" state={{ from: location.pathname + location.search }} className={styles.signIn}>
          Sign in
        </Link>
      </div>
    </div>
  );
}
