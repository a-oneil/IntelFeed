import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SettingsPage } from "../SettingsPage";

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { user: { role: string }; isAuthenticated: () => boolean }) => unknown) =>
    selector({ user: { role: "admin" }, isAuthenticated: () => true }),
}));

// The console itself is exercised in EngineSection.test.tsx — here we only
// care that the Settings section resolves and mounts it.
vi.mock("@/components/engine/EngineSection", () => ({
  EngineSection: () => <div data-testid="engine-section" />,
}));

function renderSettings(search: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[`/settings${search}`]}>
        <Routes>
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SettingsPage engine section", () => {
  it("opens the Engine section for ?section=engine", () => {
    renderSettings("?section=engine");
    expect(screen.getByTestId("engine-section")).toBeInTheDocument();
  });

  it("maps legacy ?section=schedules onto Engine", () => {
    renderSettings("?section=schedules");
    expect(screen.getByTestId("engine-section")).toBeInTheDocument();
  });

  it("maps legacy ?section=enrichment onto Engine", () => {
    renderSettings("?section=enrichment");
    expect(screen.getByTestId("engine-section")).toBeInTheDocument();
  });

  it("maps legacy ?section=feed-health onto Engine", () => {
    renderSettings("?section=feed-health");
    expect(screen.getByTestId("engine-section")).toBeInTheDocument();
  });

  it("leaves unrelated sections alone", () => {
    renderSettings("?section=appearance");
    expect(screen.queryByTestId("engine-section")).not.toBeInTheDocument();
  });
});
