import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";

// Mock useAuth hook
const mockUseRegistrationStatus = vi.fn();

vi.mock("@/hooks/useAuth", () => ({
  useLogin: vi.fn(() => ({
    mutateAsync: vi.fn(),
    isPending: false,
    isError: false,
  })),
  useRegistrationStatus: () => mockUseRegistrationStatus(),
}));

// Mock the auth store (needed by useLogin internally)
vi.mock("@/stores/authStore", () => ({
  useAuthStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      setTokens: vi.fn(),
      setUser: vi.fn(),
    })
  ),
}));

import { LoginPage } from "@/pages/LoginPage";

function renderLoginPage() {
  return render(
    <MemoryRouter>
      <LoginPage />
    </MemoryRouter>
  );
}

describe("LoginPage", () => {
  beforeEach(() => {
    mockUseRegistrationStatus.mockReturnValue({
      data: { registration_enabled: true, invite_code_required: false },
    });
  });

  it("renders the login form with username and password fields", () => {
    renderLoginPage();

    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sign In" })
    ).toBeInTheDocument();
  });

  it("shows the title and subtitle", () => {
    renderLoginPage();

    // The wordmark splits "Intel" and "Feed" across elements to accent the
    // second half, so match on the heading's accessible name.
    expect(screen.getByRole("heading", { level: 1 })).toHaveAccessibleName("IntelFeed");
    expect(screen.getByText("Monitor · Correlate · Detect")).toBeInTheDocument();
  });

  it("has a link to the register page", () => {
    renderLoginPage();

    const registerLink = screen.getByRole("link", { name: "Register" });
    expect(registerLink).toBeInTheDocument();
    expect(registerLink).toHaveAttribute("href", "/register");
  });

  it("hides the register link when registration is closed", () => {
    mockUseRegistrationStatus.mockReturnValue({
      data: { registration_enabled: false, invite_code_required: false },
    });
    renderLoginPage();

    expect(screen.queryByRole("link", { name: "Register" })).not.toBeInTheDocument();
  });

  it("hides the register link while the status is still loading", () => {
    mockUseRegistrationStatus.mockReturnValue({ data: undefined });
    renderLoginPage();

    expect(screen.queryByRole("link", { name: "Register" })).not.toBeInTheDocument();
  });
});
