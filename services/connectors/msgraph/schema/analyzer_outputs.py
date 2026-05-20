"""Pydantic models for analyzer result structures."""

from __future__ import annotations


from pydantic import BaseModel, Field


class MFACoverageResult(BaseModel):
    total_enabled_users: int = 0
    mfa_registered: int = 0
    strong_mfa: int = 0
    weak_mfa_only: int = 0
    no_mfa: int = 0
    admin_no_mfa: int = 0
    coverage_pct: float = 0.0
    strong_coverage_pct: float = 0.0


class ConditionalAccessResult(BaseModel):
    total_policies: int = 0
    enabled_policies: int = 0
    disabled_policies: int = 0
    report_only_policies: int = 0
    has_legacy_auth_block: bool = False
    has_admin_mfa_requirement: bool = False
    has_compliant_device_requirement: bool = False
    has_signin_risk_policy: bool = False
    has_user_risk_policy: bool = False
    broad_exclusion_count: int = 0
    all_users_covered: bool = False


class EnterpriseAppResult(BaseModel):
    total_apps: int = 0
    total_service_principals: int = 0
    unverified_publisher_high_priv: int = 0
    stale_apps_90d: int = 0
    new_apps_30d: int = 0
    user_consented_sensitive: int = 0
    admin_consented: int = 0


class OAuthConsentResult(BaseModel):
    total_grants: int = 0
    admin_consented: int = 0
    user_consented: int = 0
    score_3_critical: int = 0
    score_2_high: int = 0
    score_1_medium: int = 0
    stale_grants_180d: int = 0
    unverified_publisher_grants: int = 0


class AISignalResult(BaseModel):
    copilot_licensed_users: int = 0
    copilot_active_users: int = 0
    third_party_ai_apps: int = 0
    shadow_ai_apps: int = 0
    user_consented_ai: int = 0
    admin_consented_ai: int = 0
    dlp_score_3_critical: int = 0
    dlp_score_2_high: int = 0
    unapproved_ai_apps: int = 0


class GuestExposureResult(BaseModel):
    total_guests: int = 0
    stale_guests_90d: int = 0
    never_activated: int = 0
    privileged_role_guests: int = 0
    sensitive_group_guests: int = 0


class PrivilegedRoleResult(BaseModel):
    global_admin_count: int = 0
    pim_enrolled_admins: int = 0
    synced_account_admins: int = 0
    permanent_assignments: int = 0
    time_bound_assignments: int = 0
    admin_no_mfa: int = 0
    roles_by_type: dict[str, int] = Field(default_factory=dict)


class DLPExposureProfile(BaseModel):
    app_id: str
    app_category: str
    composite_score: int  # 0-9
    data_access_score: int  # 0-3
    consent_score: int  # 0-3
    publisher_trust_score: int  # 0-3
    highest_severity: str
    recommended_action: str  # block|review|accept|monitor


class DLPExposureResult(BaseModel):
    profiles: list[DLPExposureProfile] = Field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0


class AnalyzerOutputs(BaseModel):
    mfa_coverage: MFACoverageResult = Field(default_factory=MFACoverageResult)
    conditional_access: ConditionalAccessResult = Field(
        default_factory=ConditionalAccessResult
    )
    enterprise_apps: EnterpriseAppResult = Field(default_factory=EnterpriseAppResult)
    oauth_consent: OAuthConsentResult = Field(default_factory=OAuthConsentResult)
    ai_signals: AISignalResult = Field(default_factory=AISignalResult)
    guest_exposure: GuestExposureResult = Field(default_factory=GuestExposureResult)
    privileged_roles: PrivilegedRoleResult = Field(default_factory=PrivilegedRoleResult)
    dlp_exposure: DLPExposureResult = Field(default_factory=DLPExposureResult)
