"""NIST AI RMF 1.0 control registry — static seed data for questionnaire creation.

Source: NIST AI Risk Management Framework 1.0 (January 2023).
69 subcategories across four functions: GOVERN, MAP, MEASURE, MANAGE.

Each entry:
  control_id      — canonical ID (e.g. "GOVERN-1.1")
  category        — function name (GOVERN | MAP | MEASURE | MANAGE)
  function_number — subcategory group number (e.g. "1", "2")
  control_name    — short, assessor-readable description
"""

from __future__ import annotations

FRAMEWORK_ID = "nist_ai_rmf"
FRAMEWORK_VERSION = "1.0"

CONTROLS: list[dict[str, str]] = [
    # ------------------------------------------------------------------
    # GOVERN — Policies, accountability, culture, third-party governance
    # ------------------------------------------------------------------
    {
        "control_id": "GOVERN-1.1",
        "category": "GOVERN",
        "function_number": "1",
        "control_name": "Policies and processes for AI risk management are established, understood, and in place across the organization",
    },
    {
        "control_id": "GOVERN-1.2",
        "category": "GOVERN",
        "function_number": "1",
        "control_name": "Accountability and oversight roles for AI risk management are clearly defined and assigned",
    },
    {
        "control_id": "GOVERN-1.3",
        "category": "GOVERN",
        "function_number": "1",
        "control_name": "Processes for determining AI risk tolerance are established and documented",
    },
    {
        "control_id": "GOVERN-1.4",
        "category": "GOVERN",
        "function_number": "1",
        "control_name": "Processes exist to regularly incorporate external feedback into AI risk management practices",
    },
    {
        "control_id": "GOVERN-1.5",
        "category": "GOVERN",
        "function_number": "1",
        "control_name": "Organizational practices for AI risk measurement, monitoring, and management are established and maintained",
    },
    {
        "control_id": "GOVERN-1.6",
        "category": "GOVERN",
        "function_number": "1",
        "control_name": "AI worker roles, job tasks, and training expectations are documented and followed",
    },
    {
        "control_id": "GOVERN-1.7",
        "category": "GOVERN",
        "function_number": "1",
        "control_name": "Roles and responsibilities across the AI lifecycle are delineated and communicated to relevant personnel",
    },
    {
        "control_id": "GOVERN-2.1",
        "category": "GOVERN",
        "function_number": "2",
        "control_name": "Roles, responsibilities, and communication lines for AI risk management are documented and clearly communicated",
    },
    {
        "control_id": "GOVERN-2.2",
        "category": "GOVERN",
        "function_number": "2",
        "control_name": "Personnel and partners receive AI risk management awareness and training commensurate with their roles",
    },
    {
        "control_id": "GOVERN-3.1",
        "category": "GOVERN",
        "function_number": "3",
        "control_name": "AI risk-related decisions are informed by a diverse team that reflects a range of disciplines and perspectives",
    },
    {
        "control_id": "GOVERN-3.2",
        "category": "GOVERN",
        "function_number": "3",
        "control_name": "Policies and procedures define and differentiate roles for human-AI configurations and human oversight of AI systems",
    },
    {
        "control_id": "GOVERN-4.1",
        "category": "GOVERN",
        "function_number": "4",
        "control_name": "An organizational culture of critical thinking and safety-first mindset is cultivated in AI design, development, deployment, and use",
    },
    {
        "control_id": "GOVERN-4.2",
        "category": "GOVERN",
        "function_number": "4",
        "control_name": "Teams document decisions made and met and unmet AI system requirements throughout the AI lifecycle",
    },
    {
        "control_id": "GOVERN-5.1",
        "category": "GOVERN",
        "function_number": "5",
        "control_name": "Organizational policies collect, consider, prioritize, and integrate feedback from those external to the team that developed or deployed the AI system",
    },
    {
        "control_id": "GOVERN-5.2",
        "category": "GOVERN",
        "function_number": "5",
        "control_name": "Organizational practices and teams prioritize the safety, security, and robustness of deployed AI systems",
    },
    {
        "control_id": "GOVERN-6.1",
        "category": "GOVERN",
        "function_number": "6",
        "control_name": "Risk responsibilities between the organization and its third parties (AI developers, operators, users) are clearly delineated",
    },
    {
        "control_id": "GOVERN-6.2",
        "category": "GOVERN",
        "function_number": "6",
        "control_name": "Contingency processes are in place to handle failures or incidents in third-party AI systems deemed high-risk",
    },
    # ------------------------------------------------------------------
    # MAP — Context, risk identification, interdependencies
    # ------------------------------------------------------------------
    {
        "control_id": "MAP-1.1",
        "category": "MAP",
        "function_number": "1",
        "control_name": "Context is established for assessing and managing AI risks throughout the AI lifecycle",
    },
    {
        "control_id": "MAP-1.2",
        "category": "MAP",
        "function_number": "1",
        "control_name": "Organizational and stakeholder risk tolerances are determined and documented",
    },
    {
        "control_id": "MAP-1.3",
        "category": "MAP",
        "function_number": "1",
        "control_name": "AI system knowledge limits and sources of uncertainty are identified and documented",
    },
    {
        "control_id": "MAP-1.4",
        "category": "MAP",
        "function_number": "1",
        "control_name": "Operational environment characteristics that could affect AI system performance are identified and understood",
    },
    {
        "control_id": "MAP-1.5",
        "category": "MAP",
        "function_number": "1",
        "control_name": "Likelihood and magnitude of each AI risk are assessed based on context",
    },
    {
        "control_id": "MAP-1.6",
        "category": "MAP",
        "function_number": "1",
        "control_name": "Risk assessments are conducted and refreshed periodically",
    },
    {
        "control_id": "MAP-2.1",
        "category": "MAP",
        "function_number": "2",
        "control_name": "The scientific basis and research assumptions targeted in AI system design are evaluated and documented",
    },
    {
        "control_id": "MAP-2.2",
        "category": "MAP",
        "function_number": "2",
        "control_name": "Scientific principles underlying the data and AI methods used are understood and articulated",
    },
    {
        "control_id": "MAP-2.3",
        "category": "MAP",
        "function_number": "2",
        "control_name": "AI system performance and reliability are evaluated against stated objectives on a periodic basis",
    },
    {
        "control_id": "MAP-3.1",
        "category": "MAP",
        "function_number": "3",
        "control_name": "Potential benefits of the intended AI application have been reviewed and documented",
    },
    {
        "control_id": "MAP-3.2",
        "category": "MAP",
        "function_number": "3",
        "control_name": "Potential costs, externalities, and environmental impacts associated with AI system failure are examined",
    },
    {
        "control_id": "MAP-3.3",
        "category": "MAP",
        "function_number": "3",
        "control_name": "Potential impacts to individuals' rights and civil liberties from AI system use are examined",
    },
    {
        "control_id": "MAP-3.4",
        "category": "MAP",
        "function_number": "3",
        "control_name": "Risks and benefits of AI system use and foreseeable misuse are identified and documented",
    },
    {
        "control_id": "MAP-3.5",
        "category": "MAP",
        "function_number": "3",
        "control_name": "Regular engagement with relevant AI actors to capture feedback on positive, negative, and unanticipated impacts is in place",
    },
    {
        "control_id": "MAP-4.1",
        "category": "MAP",
        "function_number": "4",
        "control_name": "Approaches for measuring performance and potential negative impacts of the AI system on individuals and groups are identified",
    },
    {
        "control_id": "MAP-4.2",
        "category": "MAP",
        "function_number": "4",
        "control_name": "Intended and unintended effects of AI system use, including downstream impacts, are documented",
    },
    {
        "control_id": "MAP-5.1",
        "category": "MAP",
        "function_number": "5",
        "control_name": "Likelihood and impact of each identified AI risk are estimated and prioritized for treatment",
    },
    {
        "control_id": "MAP-5.2",
        "category": "MAP",
        "function_number": "5",
        "control_name": "Practices and personnel for supporting AI risk management and monitoring are in place and funded",
    },
    # ------------------------------------------------------------------
    # MEASURE — Testing, evaluation, monitoring
    # ------------------------------------------------------------------
    {
        "control_id": "MEASURE-1.1",
        "category": "MEASURE",
        "function_number": "1",
        "control_name": "Approaches and metrics for measuring the likelihood and impact of AI risks are identified and tracked",
    },
    {
        "control_id": "MEASURE-1.2",
        "category": "MEASURE",
        "function_number": "1",
        "control_name": "Appropriateness of AI metrics and effectiveness of existing controls are regularly assessed and updated",
    },
    {
        "control_id": "MEASURE-1.3",
        "category": "MEASURE",
        "function_number": "1",
        "control_name": "Internal experts and, as needed, external experts with relevant domain knowledge are identified and engaged",
    },
    {
        "control_id": "MEASURE-2.1",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "Test sets, evaluation metrics, and details of the performance measurement process are documented",
    },
    {
        "control_id": "MEASURE-2.2",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "Evaluations involving human subjects are conducted carefully and in compliance with applicable legal, ethical, and institutional requirements",
    },
    {
        "control_id": "MEASURE-2.3",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "AI system performance, including changes over time, is evaluated against stated objectives and benchmarks",
    },
    {
        "control_id": "MEASURE-2.4",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "Deployed AI systems are monitored to detect adverse, unintended, or unanticipated impacts",
    },
    {
        "control_id": "MEASURE-2.5",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "AI system performance is evaluated on a regular cadence appropriate to the deployment context",
    },
    {
        "control_id": "MEASURE-2.6",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "Performance measurement results are made available to relevant AI actors",
    },
    {
        "control_id": "MEASURE-2.7",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "AI system security and resilience are evaluated and documented, including resistance to adversarial inputs",
    },
    {
        "control_id": "MEASURE-2.8",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "Risks or side effects affecting stakeholders beyond direct users are identified and evaluated",
    },
    {
        "control_id": "MEASURE-2.9",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "Risk assessments are performed to identify potential impacts on individuals' rights and civil liberties",
    },
    {
        "control_id": "MEASURE-2.10",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "AI risk assessments and their findings are documented, reviewed, and updated as conditions change",
    },
    {
        "control_id": "MEASURE-2.11",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "Fairness and bias assessments are conducted periodically to evaluate potential discriminatory impacts",
    },
    {
        "control_id": "MEASURE-2.12",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "Environmental impact and sustainability of AI model training and deployment are evaluated",
    },
    {
        "control_id": "MEASURE-2.13",
        "category": "MEASURE",
        "function_number": "2",
        "control_name": "Effectiveness of the deployed AI system in achieving stated goals is evaluated periodically",
    },
    {
        "control_id": "MEASURE-3.1",
        "category": "MEASURE",
        "function_number": "3",
        "control_name": "Processes are in place to regularly identify, track, and respond to existing, unanticipated, and emerging AI risks",
    },
    {
        "control_id": "MEASURE-3.2",
        "category": "MEASURE",
        "function_number": "3",
        "control_name": "Risk tracking approaches address contexts where AI risks are difficult to assess using currently available methods",
    },
    {
        "control_id": "MEASURE-3.3",
        "category": "MEASURE",
        "function_number": "3",
        "control_name": "Feedback channels for end users and impacted communities to report problems and harms are established and publicized",
    },
    {
        "control_id": "MEASURE-4.1",
        "category": "MEASURE",
        "function_number": "4",
        "control_name": "Measurement approaches for identifying AI risks are connected to deployment context and revised as circumstances change",
    },
    {
        "control_id": "MEASURE-4.2",
        "category": "MEASURE",
        "function_number": "4",
        "control_name": "Measurement results regarding AI system trustworthiness are used to enhance organizational policies, processes, and practices",
    },
    # ------------------------------------------------------------------
    # MANAGE — Risk treatment, response, recovery, continual improvement
    # ------------------------------------------------------------------
    {
        "control_id": "MANAGE-1.1",
        "category": "MANAGE",
        "function_number": "1",
        "control_name": "A determination is made as to whether the AI system achieves its intended purpose and stated objectives and metrics",
    },
    {
        "control_id": "MANAGE-1.2",
        "category": "MANAGE",
        "function_number": "1",
        "control_name": "Treatment of identified AI risks is prioritized based on impact, likelihood, and available organizational resources",
    },
    {
        "control_id": "MANAGE-1.3",
        "category": "MANAGE",
        "function_number": "1",
        "control_name": "Responses to high-priority AI risks are developed, planned, and actively implemented",
    },
    {
        "control_id": "MANAGE-1.4",
        "category": "MANAGE",
        "function_number": "1",
        "control_name": "Negative residual risks or risk reduction plans are documented with assigned ownership",
    },
    {
        "control_id": "MANAGE-2.1",
        "category": "MANAGE",
        "function_number": "2",
        "control_name": "Resources required to manage AI risks are considered during AI design, development, and deployment planning",
    },
    {
        "control_id": "MANAGE-2.2",
        "category": "MANAGE",
        "function_number": "2",
        "control_name": "Mechanisms for achieving treatment of identified AI risks are planned and in place",
    },
    {
        "control_id": "MANAGE-2.3",
        "category": "MANAGE",
        "function_number": "2",
        "control_name": "AI risk treatment includes addressing risks posed by third-party entities within organizational risk tolerance",
    },
    {
        "control_id": "MANAGE-2.4",
        "category": "MANAGE",
        "function_number": "2",
        "control_name": "Mechanisms for detection of AI incidents and events and access to AI system documentation are established",
    },
    {
        "control_id": "MANAGE-3.1",
        "category": "MANAGE",
        "function_number": "3",
        "control_name": "AI risks and benefits from third-party resources are regularly monitored and incorporated into ongoing risk management",
    },
    {
        "control_id": "MANAGE-3.2",
        "category": "MANAGE",
        "function_number": "3",
        "control_name": "Treatment of documented AI risks follows assurance processes appropriate to high-risk AI systems",
    },
    {
        "control_id": "MANAGE-4.1",
        "category": "MANAGE",
        "function_number": "4",
        "control_name": "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and affected parties",
    },
    {
        "control_id": "MANAGE-4.2",
        "category": "MANAGE",
        "function_number": "4",
        "control_name": "Measurable continual improvement activities are integrated into AI system updates and include regular evaluation of risks, benefits, and impacts",
    },
    {
        "control_id": "MANAGE-4.3",
        "category": "MANAGE",
        "function_number": "4",
        "control_name": "Organizational policies and practices are in place to address the decommissioning of AI systems that have reached end of life or pose unacceptable risks",
    },
]

CONTROL_INDEX: dict[str, dict[str, str]] = {c["control_id"]: c for c in CONTROLS}
CATEGORIES: list[str] = ["GOVERN", "MAP", "MEASURE", "MANAGE"]
