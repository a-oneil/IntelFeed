import { useState } from "react";
import { useCreateCampaign } from "@/hooks/useCampaigns";
import styles from "./CreateCampaignModal.module.css";

interface CreateCampaignModalProps {
  onClose: () => void;
  onCreated?: (id: string) => void;
}

export const TLP_OPTIONS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"];
export const STATUS_OPTIONS = ["active", "monitoring", "closed", "historical"];

export default function CreateCampaignModal({ onClose, onCreated }: CreateCampaignModalProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState("active");
  const [tlp, setTlp] = useState("TLP:GREEN");
  const [tagsInput, setTagsInput] = useState("");
  const createCampaign = useCreateCampaign();

  const handleSubmit = () => {
    const tags = tagsInput
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    createCampaign.mutate(
      { name, description: description || undefined, status, tlp_marking: tlp, tags },
      {
        onSuccess: (campaign) => {
          onCreated?.(campaign.id);
          onClose();
        },
      }
    );
  };

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <h3 className={styles.title}>Create Campaign</h3>

        <label className={styles.label}>
          Name
          <input
            className={styles.input}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., APT29 SolarWinds"
            autoFocus
          />
        </label>

        <label className={styles.label}>
          Description
          <textarea
            className={styles.textarea}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Campaign description..."
            rows={3}
          />
        </label>

        <div className={styles.row}>
          <label className={styles.label}>
            Status
            <select className={styles.select} value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUS_OPTIONS.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </label>
          <label className={styles.label}>
            TLP Marking
            <select className={styles.select} value={tlp} onChange={(e) => setTlp(e.target.value)}>
              {TLP_OPTIONS.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </label>
        </div>

        <label className={styles.label}>
          Tags (comma-separated)
          <input
            className={styles.input}
            value={tagsInput}
            onChange={(e) => setTagsInput(e.target.value)}
            placeholder="apt, supply-chain, nation-state"
          />
        </label>

        <div className={styles.actions}>
          <button className={styles.cancelBtn} onClick={onClose}>Cancel</button>
          <button
            className={styles.createBtn}
            onClick={handleSubmit}
            disabled={!name.trim() || createCampaign.isPending}
          >
            {createCampaign.isPending ? "Creating..." : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
