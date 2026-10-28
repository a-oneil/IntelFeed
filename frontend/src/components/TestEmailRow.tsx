import { useState } from "react";
import { toast } from "sonner";
import api from "@/api/client";
import styles from "./SystemSettings.module.css";

/** Sends one message through the *saved* SMTP settings, so a typo shows up
 *  here instead of in a rule's run log. Rendered inside the Email (SMTP)
 *  group as one more setting row. */
export function TestEmailRow() {
  const [to, setTo] = useState("");
  const [sending, setSending] = useState(false);

  const send = async () => {
    setSending(true);
    try {
      await api.post("/system-settings/email/test", { to: to.trim() });
      toast.success(`Test email sent to ${to.trim()}`);
    } catch (err) {
      const msg = (err as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message;
      toast.error(msg ?? "Test email failed");
    } finally {
      setSending(false);
    }
  };

  return (
    <div className={styles.settingRow}>
      <div className={styles.settingInfo}>
        <span className={styles.settingLabel}>Send Test Email</span>
        <span className={styles.settingHint}>Uses the saved settings, so save your changes first</span>
      </div>
      <form
        className={styles.settingControl}
        onSubmit={(e) => {
          e.preventDefault();
          if (to.trim() && !sending) void send();
        }}
      >
        <input
          type="email"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="you@example.com"
          className={styles.input}
          aria-label="Send a test email to"
        />
        <button type="submit" disabled={!to.trim() || sending} className={styles.inlineBtn}>
          {sending ? "Sending…" : "Send"}
        </button>
      </form>
    </div>
  );
}
