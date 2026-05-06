import { create } from 'zustand';

// ─── Org onboarding state ────────────────────────────────────────────────────

export type Industry =
  | 'banking'
  | 'healthcare'
  | 'legal'
  | 'defense'
  | 'technology'
  | 'insurance'
  | 'other';

export type OrgProfile =
  | 'smb_basic'
  | 'smb_growth'
  | 'midmarket'
  | 'enterprise'
  | 'regulated'
  | 'govcon';

export interface OnboardingData {
  orgName: string;
  email: string;
  industry: Industry | '';
  employeeCount: string;
  revenue: string;
  handlesPhi: boolean;
  handlesCui: boolean;
  isDodContractor: boolean;
  fedrampRequired: boolean;
}

interface OnboardingStore {
  step: number;
  data: OnboardingData;
  orgId: string | null;
  assessmentId: string | null;
  setStep: (step: number) => void;
  setData: (partial: Partial<OnboardingData>) => void;
  setOrgId: (id: string) => void;
  setAssessmentId: (id: string) => void;
  reset: () => void;
}

const defaultOnboarding: OnboardingData = {
  orgName: '',
  email: '',
  industry: '',
  employeeCount: '',
  revenue: '',
  handlesPhi: false,
  handlesCui: false,
  isDodContractor: false,
  fedrampRequired: false,
};

export const useOnboardingStore = create<OnboardingStore>((set) => ({
  step: 0,
  data: defaultOnboarding,
  orgId: null,
  assessmentId: null,
  setStep: (step) => set({ step }),
  setData: (partial) => set((s) => ({ data: { ...s.data, ...partial } })),
  setOrgId: (id) => set({ orgId: id }),
  setAssessmentId: (id) => set({ assessmentId: id }),
  reset: () => set({ step: 0, data: defaultOnboarding, orgId: null, assessmentId: null }),
}));

// ─── Assessment session state ────────────────────────────────────────────────

export interface AssessmentQuestion {
  id: string;
  domain: string;
  text: string;
  type: 'boolean' | 'scale' | 'select' | 'text';
  options?: string[];
  weight: number;
}

export interface AssessmentResponse {
  questionId: string;
  value: boolean | number | string;
}

interface AssessmentStore {
  questions: AssessmentQuestion[];
  responses: Record<string, AssessmentResponse['value']>;
  currentIndex: number;
  lastSaved: Date | null;
  setQuestions: (questions: AssessmentQuestion[]) => void;
  setResponse: (questionId: string, value: AssessmentResponse['value']) => void;
  setCurrentIndex: (index: number) => void;
  setLastSaved: (date: Date) => void;
  reset: () => void;
}

export const useAssessmentStore = create<AssessmentStore>((set) => ({
  questions: [],
  responses: {},
  currentIndex: 0,
  lastSaved: null,
  setQuestions: (questions) => set({ questions }),
  setResponse: (questionId, value) =>
    set((s) => ({ responses: { ...s.responses, [questionId]: value } })),
  setCurrentIndex: (index) => set({ currentIndex: index }),
  setLastSaved: (date) => set({ lastSaved: date }),
  reset: () => set({ questions: [], responses: {}, currentIndex: 0, lastSaved: null }),
}));
