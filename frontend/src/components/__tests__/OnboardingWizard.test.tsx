import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const mockCreateProviderMutateAsync = vi.fn().mockResolvedValue({});

vi.mock("@/stores/authStore", () => ({
  useAuthStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({ user: { id: "u1", role: "admin" } })
  ),
}));

vi.mock("@/hooks/useAuth", () => ({
  useUpdateProfile: vi.fn(() => ({ mutate: vi.fn(), mutateAsync: vi.fn() })),
}));

vi.mock("@/hooks/useFeeds", () => ({
  useFeeds: vi.fn(() => ({ data: { total: 0, items: [] } })),
  useAddFeed: vi.fn(() => ({ mutateAsync: vi.fn(), isPending: false })),
}));

vi.mock("@/hooks/useAI", () => ({
  useCreateAIProvider: vi.fn(() => ({ mutateAsync: mockCreateProviderMutateAsync, isPending: false })),
}));

vi.mock("@/hooks/useThemes", () => ({
  useThemes: vi.fn(() => ({ data: [] })),
  useSetThemePreference: vi.fn(() => ({ mutate: vi.fn() })),
}));

import { OnboardingWizard } from "../OnboardingWizard";

function renderWizard() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <OnboardingWizard />
    </QueryClientProvider>
  );
}

async function goToAiStep() {
  const user = userEvent.setup();
  renderWizard();
  await user.click(screen.getByText("Next")); // welcome -> import
  await user.click(screen.getByText("Next")); // import -> feeds
  await user.click(screen.getByText("Next")); // feeds -> ai
  return user;
}

describe("OnboardingWizard AI step", () => {
  it("offers claude, ollama, and openai_compatible provider types", async () => {
    await goToAiStep();
    const options = screen.getAllByRole("option").map((o) => o.textContent);
    expect(options.some((t) => t?.includes("Claude"))).toBe(true);
    expect(options.some((t) => t?.includes("Ollama"))).toBe(true);
    expect(options.some((t) => t?.includes("OpenAI-compatible"))).toBe(true);
  });

  it("shows a base URL field for ollama and openai_compatible, not for claude", async () => {
    const user = await goToAiStep();
    expect(screen.queryByPlaceholderText(/Base URL/)).toBeNull();

    await user.selectOptions(screen.getByRole("combobox"), "openai_compatible");
    expect(screen.getByPlaceholderText(/Base URL/)).toBeDefined();
    expect(screen.getByPlaceholderText("API key (optional for local servers)")).toBeDefined();
  });

  it("clears a typed base URL when switching back to claude", async () => {
    const user = await goToAiStep();
    await user.selectOptions(screen.getByRole("combobox"), "openai_compatible");
    await user.type(screen.getByPlaceholderText(/Base URL/), "http://localhost:1234/v1");

    await user.selectOptions(screen.getByRole("combobox"), "claude");
    expect(screen.queryByPlaceholderText(/Base URL/)).toBeNull();
    expect(screen.getByPlaceholderText("Anthropic API Key")).toBeDefined();
  });

  it("does not submit a base_url when saving a claude provider", async () => {
    const user = await goToAiStep();
    await user.selectOptions(screen.getByRole("combobox"), "openai_compatible");
    await user.type(screen.getByPlaceholderText(/Base URL/), "http://localhost:1234/v1");
    await user.selectOptions(screen.getByRole("combobox"), "claude");
    await user.type(screen.getByPlaceholderText("Anthropic API Key"), "sk-ant-test");

    await user.click(screen.getByText("Save Provider"));

    expect(mockCreateProviderMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({ provider_type: "claude", base_url: undefined, api_key: "sk-ant-test" })
    );
  });
});
