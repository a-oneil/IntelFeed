import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi } from "vitest";

const mockNavigate = vi.fn();
vi.mock("react-router-dom", () => ({
  useNavigate: () => mockNavigate,
}));

vi.mock("@/api/client", () => ({
  default: { get: vi.fn(), post: vi.fn() },
}));

vi.mock("@/stores/intelStore", () => ({
  useIntelStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      setPivotEntity: vi.fn(),
    })
  ),
}));

import { RuleEntryCard } from "../RuleEntryCard";

describe("RuleEntryCard", () => {
  it("renders nothing for non-rule content types", () => {
    const { container } = render(
      <RuleEntryCard metadata={{ content_type: "markdown" }} />
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders nothing when no content_type", () => {
    const { container } = render(
      <RuleEntryCard metadata={{}} />
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders Sigma rule card with type badge", () => {
    render(
      <RuleEntryCard
        metadata={{
          source: "github_repo",
          content_type: "sigma_rule",
          owner: "SigmaHQ",
          repo: "sigma",
          file_path: "rules/test.yml",
          commit_sha: "abc123",
          change_type: "added",
          extracted: {
            rule_title: "Suspicious PS Exec",
            rule_level: "high",
            rule_author: "Florian Roth",
            mitre_attack_ids: ["T1059.001", "T1027"],
            mitre_tactics: ["execution"],
          },
        }}
      />
    );

    expect(screen.getByText("SIGMA")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("New")).toBeInTheDocument();
    expect(screen.getByText("Florian Roth")).toBeInTheDocument();
    expect(screen.getByText("T1059.001")).toBeInTheDocument();
    expect(screen.getByText("T1027")).toBeInTheDocument();
    expect(screen.getByText("execution")).toBeInTheDocument();
    expect(screen.getByText("View on GitHub")).toHaveAttribute(
      "href",
      "https://github.com/SigmaHQ/sigma/blob/abc123/rules/test.yml"
    );
  });

  it("renders Elastic rule card", () => {
    render(
      <RuleEntryCard
        metadata={{
          content_type: "elastic_rule",
          extracted: {
            rule_name: "LSASS Access",
            rule_severity: "high",
            mitre_attack_ids: ["T1003.001"],
            mitre_tactics: [],
          },
        }}
      />
    );

    expect(screen.getByText("ELASTIC")).toBeInTheDocument();
    expect(screen.getByText("T1003.001")).toBeInTheDocument();
  });

  it("renders YARA rule card", () => {
    render(
      <RuleEntryCard
        metadata={{
          content_type: "yara_rule",
          extracted: {
            mitre_attack_ids: [],
            mitre_tactics: [],
          },
        }}
      />
    );

    expect(screen.getByText("YARA")).toBeInTheDocument();
  });

  it("renders LOLBAS card", () => {
    render(
      <RuleEntryCard
        metadata={{
          content_type: "lolbas_entry",
          extracted: {
            binary_name: "certutil.exe",
            mitre_attack_ids: ["T1105"],
            mitre_tactics: ["command-and-control"],
          },
        }}
      />
    );

    expect(screen.getByText("LOLBAS")).toBeInTheDocument();
    expect(screen.getByText("T1105")).toBeInTheDocument();
  });

  it("renders Atomic test card", () => {
    render(
      <RuleEntryCard
        metadata={{
          content_type: "atomic_test",
          extracted: {
            technique_id: "T1059.001",
            mitre_attack_ids: ["T1059.001"],
            mitre_tactics: ["execution"],
          },
        }}
      />
    );

    expect(screen.getByText("ATOMIC")).toBeInTheDocument();
  });

  it("navigates to intelligence page on technique click", async () => {
    const user = userEvent.setup();
    render(
      <RuleEntryCard
        metadata={{
          content_type: "sigma_rule",
          extracted: {
            mitre_attack_ids: ["T1059.001"],
            mitre_tactics: [],
          },
        }}
      />
    );

    await user.click(screen.getByText("T1059.001"));
    expect(mockNavigate).toHaveBeenCalledWith(
      "/workbench?search=T1059.001&type=ttp"
    );
  });

  it("navigates to CVE page on CVE click", async () => {
    const user = userEvent.setup();
    render(
      <RuleEntryCard
        metadata={{
          content_type: "yara_rule",
          extracted: {
            cve_ids: ["CVE-2023-1234"],
            mitre_attack_ids: [],
            mitre_tactics: [],
          },
        }}
      />
    );

    await user.click(screen.getByText("CVE-2023-1234"));
    expect(mockNavigate).toHaveBeenCalledWith(
      "/workbench?search=CVE-2023-1234&type=cve"
    );
  });

  it("shows change type badge for modified files", () => {
    render(
      <RuleEntryCard
        metadata={{
          content_type: "sigma_rule",
          change_type: "modified",
          extracted: {
            mitre_attack_ids: [],
            mitre_tactics: [],
          },
        }}
      />
    );

    expect(screen.getByText("Modified")).toBeInTheDocument();
  });

  it("does not show GitHub link when missing commit info", () => {
    render(
      <RuleEntryCard
        metadata={{
          content_type: "sigma_rule",
          extracted: {
            mitre_attack_ids: [],
            mitre_tactics: [],
          },
        }}
      />
    );

    expect(screen.queryByText("View on GitHub")).not.toBeInTheDocument();
  });
});
