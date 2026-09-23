from app.models.ai_analysis import AIAnalysisRequest, AIBatchJob

# Phase 4: AI & Threat Intelligence
from app.models.ai_conversation import AIConversation
from app.models.ai_prompt_template import AIPromptTemplate
from app.models.ai_provider import AIProvider
from app.models.ai_result import AIResult
from app.models.ai_task import AITask
from app.models.ai_task_assignment import AITaskAssignment
from app.models.automation_log import AutomationLog

# Phase 5: Automation
from app.models.automation_rule import AutomationRule

# Phase 9-12: Detection Engineering, Threat Intelligence, Enrichment
from app.models.campaign import Campaign, CampaignEntity, CampaignEntry, CampaignSavedSearch
from app.models.category import Category
from app.models.comment import Comment, CommentMention
from app.models.correlation_event import CorrelationEventRecord
from app.models.country import Country, EntryCountry
from app.models.country_junction import CampaignCountry, ThreatActorTargetCountry
from app.models.cve import CVE, EntryCVE
from app.models.cve_affected import CVEAffected
from app.models.cwe import CWE, CVEWeakness, EntryCWE
from app.models.dashboard import Dashboard, DashboardWidget
from app.models.detection_rule import DetectionRule
from app.models.detection_rule_version import DetectionRuleVersion
from app.models.detection_summary import DetectionSummary
from app.models.enrichment import EnrichmentResult, EnrichmentSource, UserEnrichmentOverride
from app.models.entity_field_claim import EntityFieldClaim

# Entity link AI validation
from app.models.entity_index import (
    EntityAliasIndex,  # noqa: F401 — kept for model registration/re-export
    EntityNameDenylist,  # noqa: F401 — kept for model registration/re-export
    KnownAliasMap,  # noqa: F401 — kept for model registration/re-export
)
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import (
    ActorDescriptionHistory,  # noqa: F401 — kept for model registration/re-export
    EntityMaintenanceLog,  # noqa: F401 — kept for model registration/re-export
    EntityMergeSuggestionDismissal,
    EntityReclassifyTombstone,
)
from app.models.entity_note import EntityNote
from app.models.entity_relationship import EntityRelationship
from app.models.entry import Entry
from app.models.entry_embedding import EntryEmbedding
from app.models.entry_media import EntryMedia
from app.models.entry_pipeline_run import EntryPipelineRun
from app.models.entry_sector import EntrySector
from app.models.entry_signal import EntrySignal
from app.models.entry_signal_feedback import EntrySignalFeedback
from app.models.entry_state import UserEntryState
from app.models.false_positive_record import FalsePositiveRecord
from app.models.feed import Feed

# Glossary
from app.models.glossary_term import GlossaryTerm
from app.models.intel_profile import IntelProfile
from app.models.intel_report import IntelReport, IntelReportVersion
from app.models.intelligence_requirement import IntelligenceRequirement, RequirementMatch
from app.models.job_run import JobRun
from app.models.log_type_alias import LogTypeAlias
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.mitigation import EntryMitigation, Mitigation, TTPMitigation
from app.models.narrative_theme import NarrativeBriefing, NarrativeThemeMember
from app.models.note import Note
from app.models.observable import EntryObservable, Observable
from app.models.pending_autolink import PendingAutolinkMatch
from app.models.pipeline_plan import PipelinePlan
from app.models.playback_progress import PlaybackProgress
from app.models.podcast import Podcast
from app.models.product import EntryProduct, Product
from app.models.ransomware import RansomwareVictim, VictimDisclosure
from app.models.report_template import ReportTemplate
from app.models.rule_coverage import RuleCoverage
from app.models.saved_search import SavedSearch

# Sharing
from app.models.shared_entry import SharedEntry
from app.models.story_thread import StoryThread, StoryThreadBeat, StoryThreadEntry, UserThreadState

# System
from app.models.system_setting import SystemSettings
from app.models.tag import EntryTag, Tag

# Telegram mentions
from app.models.telegram_mention import TelegramChannelMention, TelegramLinkMention
from app.models.telemetry_source import TelemetrySource

# Phase 6: Dashboards & Themes
from app.models.theme import Theme
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.threat_board_state import ThreatBoardState
from app.models.tool import EntryTool, Tool
from app.models.ttp import TTP, EntryTTP
from app.models.tts_audio import TTSAudio
from app.models.user import User
from app.models.user_entity_watch import UserEntityWatch
from app.models.user_feed_subscription import UserFeedSubscription
from app.models.user_signal_weight import UserSignalWeight
from app.models.vendor import EntryVendor, Vendor
from app.models.webhook_preset import WebhookPreset

__all__ = [
    "User",
    "Feed",
    "Category",
    "Entry",
    "UserEntryState",
    "EntryEmbedding",
    "EntryMedia",
    "Podcast",
    "PlaybackProgress",
    "Note",
    "SavedSearch",
    "Tag",
    "EntryTag",
    # Phase 4
    "AIProvider",
    "AITask",
    "AIPromptTemplate",
    "AITaskAssignment",
    "AIResult",
    "AIConversation",
    "TTP",
    "EntryTTP",
    "TTSAudio",
    "CVE",
    "CVEAffected",
    "CWE",
    "EntryCWE",
    "CVEWeakness",
    "EntryCVE",
    "EntryObservable",
    "Observable",
    "ThreatActor",
    "EntryThreatActor",
    "MalwareFamily",
    "EntryMalware",
    "NarrativeBriefing",
    "NarrativeThemeMember",
    "Country",
    "EntryCountry",
    "EntrySector",
    "ThreatActorTargetCountry",
    "CampaignCountry",
    "Mitigation",
    "EntryMitigation",
    "TTPMitigation",
    "Tool",
    "EntryTool",
    "PendingAutolinkMatch",
    "Vendor",
    "EntryVendor",
    "Product",
    "EntryProduct",
    "RansomwareVictim",
    "VictimDisclosure",
    "DetectionRule",
    "CorrelationEventRecord",
    # Phase 5
    "AutomationRule",
    "AutomationLog",
    "WebhookPreset",
    # Phase 6
    "Theme",
    "Dashboard",
    "DashboardWidget",
    # Phase 9-12
    "Campaign",
    "CampaignEntry",
    "CampaignEntity",
    "CampaignSavedSearch",
    "IntelligenceRequirement",
    "RequirementMatch",
    "IntelProfile",
    "IntelReport",
    "IntelReportVersion",
    "ReportTemplate",
    "DetectionRuleVersion",
    "EntityRelationship",
    "EntityNote",
    "EntityFieldClaim",
    "TelemetrySource",
    "RuleCoverage",
    "LogTypeAlias",
    "ThreatBoardState",
    "Comment",
    "CommentMention",
    "EnrichmentSource",
    "UserEnrichmentOverride",
    "EnrichmentResult",
    "DetectionSummary",
    "FalsePositiveRecord",
    # Glossary
    "GlossaryTerm",
    # System
    "SystemSettings",
    # Sharing
    "SharedEntry",
    "StoryThread",
    "StoryThreadBeat",
    "StoryThreadEntry",
    "UserThreadState",
    # Telegram mentions
    "TelegramChannelMention",
    "TelegramLinkMention",
    # Entity link AI validation
    "EntityLinkValidationLog",
    # Entity maintenance / dedup
    "EntityMergeSuggestionDismissal",
    "EntityReclassifyTombstone",
    # Signal engine
    "EntrySignal",
    "EntrySignalFeedback",
    # Pipeline run visibility
    "EntryPipelineRun",
    # Pipeline plans
    "PipelinePlan",
    # Job observability
    "JobRun",
    # Entity watchlist
    "UserEntityWatch",
    "UserFeedSubscription",
    "UserSignalWeight",
    # One-pass AI analysis queue
    "AIAnalysisRequest",
    "AIBatchJob",
]
