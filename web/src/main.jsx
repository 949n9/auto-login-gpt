import { AccountDetails, CopyCredentialsButton, securityActionLabel, securityOperationSummary } from "./account-details.jsx";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Ban,
  CalendarClock,
  Check,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  CircleAlert,
  Clock3,
  Copy,
  Download,
  ExternalLink,
  FileText,
  Filter,
  Globe2,
  KeyRound,
  ListPlus,
  LoaderCircle,
  LogIn,
  LogOut,
  Mail,
  MailCheck,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Send,
  Settings2,
  ShieldCheck,
  Smartphone,
  PhoneIncoming,
  Trash2,
  X,
} from "lucide-react";
import "./styles.css";
import { LEGACY_PROXY_STORAGE_KEY, PROXY_LIBRARY_STORAGE_KEY, ProxyAssignments, ProxyManager, ProxySelect, normalizeProxyState, readProxyState, selectedProxyUrl, DEFAULT_OPERATION_PROXY_ID, operationProxySelection } from "./proxy-controls.jsx";
import { CrsToolbar, CrsUploadButton, CrsAccountSettings, CrsBatchSettingsButton, useCrsIntegration } from "./crs-controls.jsx";
import { ScheduledTasksDialog } from "./scheduled-tasks.jsx";
import { AccountAreaTabs, AccountTermSelect, RestingStatus, RetiredStatus } from "./account-lifecycle.jsx";

const POLL_INTERVAL_MS = 900;
const LUBAN_API_KEY_STORAGE_KEY = "chatgpt-onboarding.luban-api-key";
const LUBAN_SERVICE_ID_STORAGE_KEY = "chatgpt-onboarding.luban-service-id";
const SMS_PROVIDER_SETTINGS_KEY = "chatgpt-onboarding.sms-provider-settings-v1";
const MAIL_REQUEST_SETTINGS_KEY = "chatgpt-onboarding.mail-request-settings-v1";
const SUB2API_UPLOAD_SETTINGS_KEY = "chatgpt-onboarding.sub2api-upload-settings-v1";
const SETTINGS_SECTION_LABELS = { proxyLibrary: "代理列表", sms: "接码平台配置", mail: "邮件 API 配置", sub2api: "Sub2API 配置" };
const SMS_PROVIDER_EXTERNAL_LINKS = {
  luban: {
    href: "https://lubansms.com/",
    label: "点击获取 API 密钥",
  },
  smsbower: {
    href: "https://smsbower.app/cabinet/profile",
    label: "点击获取 API 密钥",
  },
};
const REGION_NAMES = typeof Intl.DisplayNames === "function"
  ? new Intl.DisplayNames(["zh-CN"], { type: "region" })
  : null;

function App() {
  const [token, setToken] = useState("");
  const crs = useCrsIntegration(token);
  const [features, setFeatures] = useState({});
  const [initializationAttempt, setInitializationAttempt] = useState(0);
  const [initializationError, setInitializationError] = useState("");
  const [settingsReady, setSettingsReady] = useState(false);
  const [settingsError, setSettingsError] = useState("");
  const [settingsSavingSection, setSettingsSavingSection] = useState("");
  const settingsRevisions = useRef({});
  const settingsSaveInFlight = useRef(false);
  const [jobs, setJobs] = useState([]);
  const [email, setEmail] = useState("");
  const [accountTerm, setAccountTerm] = useState("long");
  const [accountArea, setAccountArea] = useState("active");
  const [areaCounts, setAreaCounts] = useState({ active: 0, resting: 0, retired: 0, all: 0 });
  const [addLoginMode, setAddLoginMode] = useState("save");
  const startLoginOnAdd = addLoginMode !== "save";
  const addLoginFlow = addLoginMode === "legacy" ? "legacy" : "codex";
  const [busy, setBusy] = useState(false);
  const [batchOpen, setBatchOpen] = useState(false);
  const [scheduledTasksOpen, setScheduledTasksOpen] = useState(false);
  const [batchText, setBatchText] = useState("");
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchError, setBatchError] = useState("");
  const [batchPreview, setBatchPreview] = useState(null);
  const [batchAccountTerm, setBatchAccountTerm] = useState("long");
  const [batchAccountTerms, setBatchAccountTerms] = useState({});
  const [batchProxyAssignments, setBatchProxyAssignments] = useState({});
  const [proxyAction, setProxyAction] = useState(null);
  const [actionProxyAssignments, setActionProxyAssignments] = useState({});
  const [proxyActionError, setProxyActionError] = useState("");
  const [securityUseStoredProxy, setSecurityUseStoredProxy] = useState(true);
  const [proxyActionResult, setProxyActionResult] = useState(null);
  const [securityChooser, setSecurityChooser] = useState(null);
  const [filterOpen, setFilterOpen] = useState(false);
  const [filterText, setFilterText] = useState("");
  const [filterError, setFilterError] = useState("");
  const [emailFilter, setEmailFilter] = useState([]);
  const [proxyChange, setProxyChange] = useState(null);
  const [proxyChangeId, setProxyChangeId] = useState("");
  const [proxyChangeError, setProxyChangeError] = useState("");
  const [proxyChangeBusy, setProxyChangeBusy] = useState(false);
  const [accountSearch, setAccountSearch] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [error, setError] = useState("");
  const [expandedJobId, setExpandedJobId] = useState(null);
  const [selectedJobIds, setSelectedJobIds] = useState(() => new Set());
  const [jobSelectionIndex, setJobSelectionIndex] = useState([]);
  const [batchAction, setBatchAction] = useState("");
  const [page, setPage] = useState(1);
  const [pagination, setPagination] = useState({ page: 1, pageSize: 20, total: 0, totalPages: 1 });
  const [stats, setStats] = useState({ active: 0, queued: 0, completed: 0 });
  const [smsSettings, setSmsSettings] = useState(defaultSmsProviderSettings);
  const [smsSettingsOpen, setSmsSettingsOpen] = useState(false);
  const [smsSettingsDraft, setSmsSettingsDraft] = useState(defaultSmsProviderSettings);
  const [smsSettingsSaving, setSmsSettingsSaving] = useState(false);
  const [smsSettingsError, setSmsSettingsError] = useState("");
  const [smsNumberOptions, setSmsNumberOptions] = useState([]);
  const [smsOptionsLoading, setSmsOptionsLoading] = useState(false);
  const [mailRequestSettings, setMailRequestSettings] = useState(() => normalizeMailRequestSettings({}));
  const [mailRequestSettingsDraft, setMailRequestSettingsDraft] = useState(() => normalizeMailRequestSettings({}));
  const [mailRequestSettingsOpen, setMailRequestSettingsOpen] = useState(false);
  const [mailRequestSettingsError, setMailRequestSettingsError] = useState("");
  const [mailRequestSettingsSaving, setMailRequestSettingsSaving] = useState(false);
  const [sub2apiSettings, setSub2apiSettings] = useState(() => normalizeSub2ApiSettings({}));
  const [sub2apiSettingsDraft, setSub2apiSettingsDraft] = useState(() => normalizeSub2ApiSettings({}));
  const [sub2apiGroups, setSub2apiGroups] = useState([]);
  const [sub2apiProxies, setSub2apiProxies] = useState([]);
  const [sub2apiSettingsOpen, setSub2apiSettingsOpen] = useState(false);
  const [sub2apiSettingsError, setSub2apiSettingsError] = useState("");
  const [sub2apiGroupsLoading, setSub2apiGroupsLoading] = useState(false);
  const [sub2apiSettingsSaving, setSub2apiSettingsSaving] = useState(false);
  const [sub2apiMonitorChecking, setSub2apiMonitorChecking] = useState(false);
  const [sub2apiMonitorStatus, setSub2apiMonitorStatus] = useState({
    configured: false,
    enabled: false,
    running: false,
    lastCheckAt: null,
    nextCheckAt: null,
    lastError: null,
    lastResult: null,
    intervalMinutes: 5,
  });
  const [uploadNotice, setUploadNotice] = useState("");
  const [proxyState, setProxyState] = useState(() => normalizeProxyState({}));
  const [operationProxyId, setOperationProxyId] = useState(null);
  const [proxyManagerOpen, setProxyManagerOpen] = useState(false);
  const dynamicProxyRequest = useCallback((url, options) => apiFetch(token, url, options), [token]);
  const defaultOperationProxy = features.defaultOperationProxy;
  const selectedOperationProxyId = operationProxyId ?? (defaultOperationProxy?.configured ? DEFAULT_OPERATION_PROXY_ID : proxyState.selectedId);
  const selectedProxy = proxyState.proxies.find((proxy) => proxy.id === selectedOperationProxyId);
  const accountProxyUrl = selectedOperationProxyId === DEFAULT_OPERATION_PROXY_ID && defaultOperationProxy?.configured ? { useDefaultProxy: true } : selectedOperationProxyId === "direct" ? "" : selectedProxy?.dynamicProfileId ? { dynamicProfileId: selectedProxy.dynamicProfileId } : selectedProxy?.url ?? null;

  function applySharedSettings(data) {
    const settings = data.settings || {};
    settingsRevisions.current = data.revisions || {};
    setProxyState(normalizeProxyState(settings.proxyLibrary));
    setSmsSettings(normalizeSmsProviderSettings(settings.sms));
    setMailRequestSettings(normalizeMailRequestSettings(settings.mail));
    setSub2apiSettings(normalizeSub2ApiSettings(settings.sub2api));
  }

  async function saveSharedSetting(section, value) {
    if (!token || !settingsReady) throw new Error("服务器配置尚未加载，请先重新连接");
    if (settingsSaveInFlight.current) throw new Error("另一项配置正在保存，请稍后再试");
    settingsSaveInFlight.current = true;
    setSettingsSavingSection(section);
    try {
      const data = await settingsFetch(token, "/api/settings", {
        method: "PUT",
        body: JSON.stringify({ section, value, revision: settingsRevisions.current[section] || 0 }),
      });
      applySharedSettings(data);
      setSettingsError("");
      return data;
    } catch (requestError) {
      if (requestError.status === 409 && requestError.data?.settings) {
        applySharedSettings(requestError.data);
        const latest = requestError.data.settings;
        if (section === "sms") setSmsSettingsDraft(withSmsProviderDefaults(smsProviderDefinitions, normalizeSmsProviderSettings(latest.sms)));
        if (section === "mail") setMailRequestSettingsDraft(normalizeMailRequestSettings(latest.mail));
        if (section === "sub2api") setSub2apiSettingsDraft(normalizeSub2ApiSettings(latest.sub2api));
        throw new Error("其他设备已修改配置，已同步服务器最新值。请核对后再保存。");
      }
      if (requestError.status === 403) {
        setInitializationError("服务器连接凭证已失效，请重新连接");
        setSettingsReady(false);
        setToken("");
      }
      throw requestError;
    } finally {
      settingsSaveInFlight.current = false;
      setSettingsSavingSection("");
    }
  }

  async function saveProxySelection(selectedId) {
    if (defaultOperationProxy?.configured) {
      setOperationProxyId(operationProxySelection(selectedId, defaultOperationProxy));
      return;
    }
    try {
      await saveSharedSetting("proxyLibrary", { ...proxyState, selectedId });
    } catch (requestError) {
      setSettingsError(requestError.message);
    }
  }

  useEffect(() => {
    let stopped = false;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15_000);
    setToken("");
    setSettingsReady(false);
    setInitializationError("");
    const initialize = async () => {
      try {
        const bootstrap = await fetch("/api/bootstrap", { cache: "no-store", signal: controller.signal }).then(readResponse);
        if (!bootstrap.token) throw new Error("服务器未返回有效的连接凭证");
        let shared = await apiFetch(bootstrap.token, "/api/settings", { signal: controller.signal });
        const legacy = readLegacySharedSettings();
        const warnings = [...legacy.warnings];
        const missing = Object.fromEntries(Object.entries(legacy.settings).filter(([section]) => !Object.hasOwn(shared.settings || {}, section)));
        for (const [section, value] of Object.entries(missing)) {
          try {
            shared = await apiFetch(bootstrap.token, "/api/settings/migrate", {
              method: "POST", signal: controller.signal, body: JSON.stringify({ settings: { [section]: value } }),
            });
          } catch (requestError) {
            warnings.push(`旧浏览器的${SETTINGS_SECTION_LABELS[section]}未导入，请在配置中重新保存。原浏览器数据已保留。`);
          }
        }
        removeMigratedLocalSettings(legacy.settings, shared.settings || {}, legacy.keys);
        if (!stopped) {
          applySharedSettings(shared);
          setFeatures(bootstrap.features || {});
          setSettingsReady(true);
          setSettingsError(warnings.join(" "));
          setToken(bootstrap.token);
        }
      } catch (requestError) {
        if (!stopped) setInitializationError(requestError.name === "AbortError"
          ? "连接服务器超时，请检查网络后重试"
          : `加载服务器配置失败：${requestError.message}`);
      } finally {
        window.clearTimeout(timeout);
      }
    };
    void initialize();
    return () => {
      stopped = true;
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, [initializationAttempt]);

  useEffect(() => {
    if (accountSearch.trim() === searchQuery) return undefined;
    const timer = window.setTimeout(() => {
      setSearchQuery(accountSearch.trim());
      setPage(1);
      setSelectedJobIds(new Set());
      setExpandedJobId(null);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [accountSearch, searchQuery]);

  useEffect(() => {
    if (!token) return undefined;
    let stopped = false;
    let timer;
    const poll = async () => {
      try {
        const data = emailFilter.length || searchQuery
          ? await apiFetch(token, "/api/jobs/query", {
              method: "POST",
              body: JSON.stringify({ page, area: accountArea, ...(emailFilter.length ? { emails: emailFilter } : {}), search: searchQuery }),
            })
          : await apiFetch(token, `/api/jobs?page=${page}&area=${accountArea}`);
        if (!stopped) {
          setJobs(data.jobs);
          if (data.areaCounts) setAreaCounts(data.areaCounts);
          setJobSelectionIndex(data.selection || data.jobs);
          setPagination(data.pagination || { page, pageSize: 20, total: data.jobs.length, totalPages: 1 });
          setStats(data.stats || { active: 0, queued: 0, completed: 0 });
          if (data.pagination?.page && data.pagination.page !== page) setPage(data.pagination.page);
          setError("");
        }
      } catch (requestError) {
        if (!stopped && requestError.status === 403) {
          setInitializationError("服务器连接凭证已失效，请重新连接");
          setSettingsReady(false);
          setToken("");
        } else if (!stopped) setError(requestError.message);
      } finally {
        if (!stopped) timer = window.setTimeout(poll, POLL_INTERVAL_MS);
      }
    };
    poll();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [token, page, emailFilter, searchQuery, accountArea]);

  useEffect(() => {
    if (!token || !features.sub2apiMonitor) return undefined;
    let stopped = false;
    const load = async () => {
      try {
        const data = await apiFetch(token, "/api/sub2api/monitor");
        if (!stopped) {
          setSub2apiMonitorStatus(data);
          setSub2apiSettings((current) => ({ ...current, monitorEnabled: Boolean(data.enabled) }));
        }
      } catch {}
    };
    void load();
    const timer = window.setInterval(load, 5_000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [token, features.sub2apiMonitor]);

  const pageJobIds = useMemo(() => jobs.map((job) => job.id), [jobs]);
  const smsProviderDefinitions = Array.isArray(features.smsProviders) ? features.smsProviders : [];
  const activeSmsProvider = useMemo(
    () => resolveSmsProvider(smsProviderDefinitions, smsSettings),
    [smsProviderDefinitions, smsSettings],
  );
  const draftSmsProvider = useMemo(
    () => resolveSmsProvider(smsProviderDefinitions, smsSettingsDraft),
    [smsProviderDefinitions, smsSettingsDraft],
  );
  const selectedJobs = useMemo(
    () => jobSelectionIndex.filter((job) => selectedJobIds.has(job.id)),
    [jobSelectionIndex, selectedJobIds],
  );
  const downloadableSelectedCount = selectedJobs.filter((job) => job.canDownload).length;
  const allPageSelected = pageJobIds.length > 0 && pageJobIds.every((id) => selectedJobIds.has(id));
  const canDownloadSelected = selectedJobs.length > 0 && selectedJobs.length === selectedJobIds.size
    && downloadableSelectedCount > 0;
  const canReauthorizeSelected = selectedJobs.length > 0 && selectedJobs.length === selectedJobIds.size
    && selectedJobs.every((job) => job.canRegenerate || job.canRetry);
  const forceReloginSelectedCount = selectedJobs.filter((job) => job.canForceRelogin).length;
  const canForceReloginSelected = selectedJobs.length > 0 && selectedJobs.length === selectedJobIds.size
    && forceReloginSelectedCount > 0;
  const canUploadSelected = selectedJobs.length > 0 && selectedJobs.some((job) => job.canDownload && !job.loginDeferred);
  const totpSetupSelectedCount = selectedJobs.filter((job) => job.canSetupTotp).length;
  const canSetupTotpSelected = selectedJobs.length > 0 && selectedJobs.length === selectedJobIds.size
    && totpSetupSelectedCount > 0;
  const canSecuritySelected = selectedJobs.length === selectedJobIds.size && selectedJobs.some(canUseAccountSecurity);
  const securityProxies = proxyState.proxies.filter((proxy) => isSocks5ProxyUrl(proxy.url));
  const securityProxyError = proxyAction?.securityAction && !proxyActionResult
    ? validateSecurityProxySelection(proxyAction.accounts, securityUseStoredProxy, actionProxyAssignments, securityProxies, defaultOperationProxy)
    : "";
  const passwordAddSelectedCount = selectedJobs.filter((job) => job.canAddPassword).length;
  const canAddPasswordSelected = selectedJobs.length > 0 && selectedJobs.length === selectedJobIds.size
    && passwordAddSelectedCount > 0;

  async function saveAccountProxy(event) {
    event.preventDefault();
    if (proxyChangeBusy || !proxyChange) return;
    setProxyChangeBusy(true); setProxyChangeError("");
    try {
      const proxyUrl = selectedProxyUrl(proxyChangeId, proxyState.proxies.filter((proxy) => !proxy.dynamicProfileId));
      const data = await apiFetch(token, `/api/jobs/${proxyChange.id}/proxy`, { method: "POST", body: JSON.stringify({ proxyUrl }) });
      setJobs((current) => current.map((job) => job.id === data.job.id ? data.job : job));
      setProxyChange(null);
      setUploadNotice("账号代理已保存，下次账号操作时生效");
    } catch (error) { setProxyChangeError(error.message); }
    finally { setProxyChangeBusy(false); }
  }

  function openSmsSettings() {
    const draft = withSmsProviderDefaults(smsProviderDefinitions, smsSettings);
    setSmsSettingsDraft(draft);
    setSmsSettingsError("");
    setSmsSettingsOpen(true);
  }

  function openMailRequestSettings() {
    setMailRequestSettingsDraft({ ...mailRequestSettings });
    setMailRequestSettingsError("");
    setMailRequestSettingsOpen(true);
  }

  async function saveMailRequestSettings(event) {
    event.preventDefault();
    try {
      buildMailRequestConfig(mailRequestSettingsDraft);
    } catch (requestError) {
      setMailRequestSettingsError(requestError.message);
      return;
    }
    setMailRequestSettingsSaving(true);
    setMailRequestSettingsError("");
    try {
      await saveSharedSetting("mail", normalizeMailRequestSettings(mailRequestSettingsDraft));
      setMailRequestSettingsOpen(false);
    } catch (requestError) {
      setMailRequestSettingsError(requestError.message);
    } finally {
      setMailRequestSettingsSaving(false);
    }
  }

  function openSub2ApiSettings() {
    setSub2apiSettingsDraft({ ...sub2apiSettings, monitorEnabled: Boolean(sub2apiMonitorStatus.enabled) });
    setSub2apiSettingsError("");
    setSub2apiSettingsOpen(true);
  }

  async function loadSub2ApiOptions(settings = sub2apiSettingsDraft) {
    setSub2apiGroupsLoading(true);
    setSub2apiSettingsError("");
    try {
      const data = await apiFetch(token, "/api/sub2api/options", {
        method: "POST",
        body: JSON.stringify({ config: settings }),
      });
      setSub2apiGroups(Array.isArray(data.groups) ? data.groups : []);
      setSub2apiProxies(Array.isArray(data.proxies) ? data.proxies : []);
    } catch (requestError) {
      setSub2apiGroups([]);
      setSub2apiProxies([]);
      setSub2apiSettingsError(requestError.message);
    } finally {
      setSub2apiGroupsLoading(false);
    }
  }

  async function saveSub2ApiSettings(event) {
    event.preventDefault();
    const baseUrl = String(sub2apiSettingsDraft.baseUrl || "").trim();
    const adminApiKey = String(sub2apiSettingsDraft.adminApiKey || "").trim();
    if (!baseUrl || !/^https?:\/\//i.test(baseUrl)) {
      setSub2apiSettingsError("请输入 http:// 或 https:// 开头的 Sub2API 后端地址");
      return;
    }
    if (!adminApiKey) {
      setSub2apiSettingsError("请输入 Sub2API 管理员 API Key");
      return;
    }
    const nextSettings = {
      ...readSub2ApiSettings(sub2apiSettingsDraft),
      baseUrl: baseUrl.replace(/\/+$/, ""),
      adminApiKey,
    };
    setSub2apiSettingsSaving(true);
    try {
      await saveSharedSetting("sub2api", nextSettings);
      const monitor = await settingsFetch(token, "/api/sub2api/monitor");
      setSub2apiMonitorStatus(monitor);
      setSub2apiSettingsOpen(false);
      setSub2apiSettingsError("");
    } catch (requestError) {
      setSub2apiSettingsError(requestError.message);
    } finally {
      setSub2apiSettingsSaving(false);
    }
  }

  async function checkSub2ApiMonitorNow() {
    if (!sub2apiMonitorStatus.enabled || sub2apiMonitorChecking) return;
    setSub2apiMonitorChecking(true);
    setSub2apiSettingsError("");
    try {
      const data = await apiFetch(token, "/api/sub2api/monitor/check", { method: "POST" });
      setSub2apiMonitorStatus(data);
      setUploadNotice(formatMonitorResult(data.result));
      setError("");
    } catch (requestError) {
      if (sub2apiSettingsOpen) setSub2apiSettingsError(requestError.message);
      else setError(requestError.message);
    } finally {
      setSub2apiMonitorChecking(false);
    }
  }

  function setSub2ApiGroupChecked(groupId, checked) {
    setSub2apiSettingsDraft((current) => {
      const selected = new Set(current.groupIds);
      if (checked) selected.add(String(groupId));
      else selected.delete(String(groupId));
      return { ...current, groupIds: [...selected] };
    });
  }

  async function uploadSelected(ids) {
    if (!sub2apiSettings.baseUrl || !sub2apiSettings.adminApiKey) {
      openSub2ApiSettings();
      setUploadNotice("请先配置 Sub2API 后端地址、管理员 API Key 和目标号池");
      return;
    }
    if (batchAction) return;
    setBatchAction("upload");
    setUploadNotice("");
    try {
      const data = await apiFetch(token, "/api/sub2api/upload", {
        method: "POST",
        body: JSON.stringify({ ids, config: sub2apiSettings }),
      });
      const result = data.result || {};
      const created = result.account_created ?? result.success ?? data.uploaded;
      const failed = result.account_failed ?? result.failed ?? 0;
      setUploadNotice(`已上传 ${created} 条${failed ? `，失败 ${failed} 条` : ""}${data.skipped ? `，跳过未完成任务 ${data.skipped} 条` : ""}`);
      setSelectedJobIds(new Set());
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBatchAction("");
    }
  }

  async function loadSmsNumberOptions(settings = smsSettingsDraft) {
    const resolved = resolveSmsProvider(smsProviderDefinitions, settings);
    if (!resolved.definition?.optionsEndpoint) return;
    if (!String(resolved.config.apiKey || "").trim()) {
      setSmsSettingsError("请先填写 API Key");
      return;
    }
    setSmsOptionsLoading(true);
    setSmsSettingsError("");
    try {
      const data = await apiFetch(token, resolved.definition.optionsEndpoint, {
        method: "POST",
        body: JSON.stringify({ config: resolved.config }),
      });
      const options = Array.isArray(data.options) ? data.options : [];
      setSmsNumberOptions(options);
      const current = resolved.config.maxPrice
        ? options.find((option) => option.country === resolved.config.country) || options[0]
        : options[0];
      if (!current) throw new Error("当前没有可购买的国家号码");
      updateSmsProviderConfig(resolved.id, {
        country: current.country,
        maxPrice: String(current.price),
        countryLabel: formatSmsCountryName(current),
      });
    } catch (requestError) {
      setSmsNumberOptions([]);
      setSmsSettingsError(requestError.message);
    } finally {
      setSmsOptionsLoading(false);
    }
  }

  function updateSmsProviderConfig(providerId, values) {
    setSmsSettingsDraft((current) => ({
      ...current,
      configs: {
        ...(current.configs || {}),
        [providerId]: {
          ...(current.configs?.[providerId] || {}),
          ...values,
        },
      },
    }));
  }

  async function saveSmsSettings(event) {
    event.preventDefault();
    const resolved = resolveSmsProvider(smsProviderDefinitions, smsSettingsDraft);
    if (!resolved.definition) {
      setSmsSettingsError("请选择接码平台");
      return;
    }
    const missing = resolved.definition.fields.find((field) => (
      field.required !== false && !String(resolved.config[field.key] || "").trim()
    ));
    if (missing) {
      setSmsSettingsError(`请填写${missing.label}`);
      return;
    }
    if (resolved.id === "custom") {
      const customEntries = inspectCustomSmsEntries(resolved.config.entries);
      if (customEntries.error) {
        setSmsSettingsError(customEntries.error);
        return;
      }
    }
    setSmsSettingsSaving(true);
    setSmsSettingsError("");
    try {
      await saveSharedSetting("sms", withSmsProviderDefaults(smsProviderDefinitions, smsSettingsDraft));
      setSmsSettingsOpen(false);
    } catch (requestError) {
      setSmsSettingsError(requestError.message);
    } finally {
      setSmsSettingsSaving(false);
    }
  }

  useEffect(() => {
    const valid = new Set(jobSelectionIndex.map((job) => job.id));
    setSelectedJobIds((current) => {
      const next = new Set([...current].filter((id) => valid.has(id)));
      if (next.size === current.size && [...next].every((id) => current.has(id))) return current;
      return next;
    });
  }, [jobSelectionIndex]);

  useEffect(() => {
    setExpandedJobId(null);
  }, [page]);

  function changeAccountArea(area) {
    if (area === accountArea) return;
    setAccountArea(area);
    setPage(1);
    setJobs([]);
    setJobSelectionIndex([]);
    setSelectedJobIds(new Set());
    setExpandedJobId(null);
  }

  function updateAccountTerm(updated) {
    setJobs((current) => current.map((job) => job.email === updated.email ? { ...job, accountTerm: updated.accountTerm } : job));
    setJobSelectionIndex((current) => current.map((job) => job.email === updated.email ? { ...job, accountTerm: updated.accountTerm } : job));
  }

  async function moveSelectedAccounts(area) {
    const label = area === "rest" ? "静置区" : "废号区";
    if (!window.confirm(`将选中的 ${selectedJobs.length} 个账号移到${label}？移入后暂停自动登录和推送，资料会保留。`)) return;
    setBatchAction(`move-${area}`);
    let moved = 0;
    const errors = [];
    try {
      for (const job of selectedJobs) {
        try {
          await apiFetch(token, `/api/jobs/${job.id}/${area}`, { method: "POST", body: JSON.stringify(area === "retire" ? { reason: "手动移入废号区" } : {}) });
          moved += 1;
        } catch (failure) { errors.push(`${job.email}：${failure.message}`); }
      }
      setSelectedJobIds(new Set());
      setError(errors.length ? `已移动 ${moved} 个；${errors.join("；")}` : "");
    } finally { setBatchAction(""); }
  }

  async function createJob(event) {
    event.preventDefault();
    if (!email.trim() || busy) return;
    setBusy(true);
    try {
      const data = await apiFetch(token, "/api/jobs", {
        method: "POST",
        body: JSON.stringify({ email: email.trim(), accountTerm, startLogin: startLoginOnAdd, loginFlow: addLoginFlow, ...(startLoginOnAdd ? { proxyUrl: requireSelectedProxyUrl(accountProxyUrl) } : {}) }),
      });
      if (accountArea !== "active") changeAccountArea("active");
      setPage(1);
      setSelectedJobIds(new Set());
      if (page === 1 && accountArea === "active" && !data.job.resting && !data.job.retired) setJobs((current) => mergeJobs([data.job], current).slice(0, 20));
      setEmail("");
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function createBatch(event) {
    event.preventDefault();
    if (!batchText.trim() || batchBusy) return;
    setBatchBusy(true);
    try {
      if (!batchPreview) {
        const preview = await apiFetch(token, "/api/jobs/preview", {
          method: "POST",
          body: JSON.stringify({ text: batchText }),
        });
        setBatchPreview(preview.accounts.map((account) => ({ key: account.email.toLowerCase(), email: account.email })));
        setBatchProxyAssignments({});
        setBatchAccountTerms({});
        setBatchError("");
        return;
      }
      const proxyAssignments = startLoginOnAdd ? batchPreview.map((account) => ({ email: account.email, proxyUrl: selectedProxyUrl(batchProxyAssignments[account.key], proxyState.proxies, defaultOperationProxy) })) : undefined;
      const data = await apiFetch(token, "/api/jobs/batch", {
        method: "POST",
        body: JSON.stringify({ text: batchText, accountTerm: batchAccountTerm, accountTerms: batchPreview.map((account) => ({ email: account.email, accountTerm: batchAccountTerms[account.key] || batchAccountTerm })), startLogin: startLoginOnAdd, loginFlow: addLoginFlow, ...(proxyAssignments ? { proxyAssignments } : {}) }),
      });
      if (accountArea !== "active") changeAccountArea("active");
      setPage(1);
      setSelectedJobIds(new Set());
      if (page === 1 && accountArea === "active") setJobs((current) => mergeJobs(data.jobs.filter((job) => !job.resting && !job.retired), current).slice(0, 20));
      setBatchText("");
      setBatchPreview(null);
      setBatchProxyAssignments({});
      setBatchAccountTerms({});
      setBatchError("");
      setBatchOpen(false);
      setError("");
    } catch (requestError) {
      setBatchError(requestError.message);
    } finally {
      setBatchBusy(false);
    }
  }

  function applyEmailFilter(event) {
    event.preventDefault();
    try {
      const emails = parseEmailFilter(filterText);
      setEmailFilter(emails);
      setSelectedJobIds(new Set());
      setExpandedJobId(null);
      setPage(1);
      setFilterError("");
      setFilterOpen(false);
    } catch (filterParseError) {
      setFilterError(filterParseError.message);
    }
  }

  function clearEmailFilter() {
    setEmailFilter([]);
    setFilterText("");
    setSelectedJobIds(new Set());
    setExpandedJobId(null);
    setPage(1);
    setFilterError("");
  }

  function toggleJobSelection(jobId) {
    setSelectedJobIds((current) => {
      const next = new Set(current);
      if (next.has(jobId)) next.delete(jobId);
      else next.add(jobId);
      return next;
    });
  }

  function toggleAllOnPage() {
    setSelectedJobIds((current) => {
      const next = new Set(current);
      pageJobIds.forEach((id) => {
        if (allPageSelected) next.delete(id);
        else next.add(id);
      });
      return next;
    });
  }

  async function downloadSelected() {
    if (!canDownloadSelected || batchAction) return;
    setBatchAction("download");
    try {
      const response = await fetch("/api/jobs/download-batch", {
        method: "POST",
        headers: { "content-type": "application/json", "x-console-token": token },
        body: JSON.stringify({ ids: [...selectedJobIds] }),
      });
      if (!response.ok) throw new Error((await response.json()).error || "批量下载失败");
      await saveDownloadResponse(response, `sub2api-import-oauth-${downloadableSelectedCount}-accounts-${localTimestamp()}.json`);
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBatchAction("");
    }
  }

  function prepareProxyAction(kind, title, eligible, loginFlow = "codex") {
    const accounts = selectedJobs.map((job) => ({ key: job.id, email: job.email, currentEndpoint: job.proxyEndpoint || null, skipped: !eligible(job) }));
    setActionProxyAssignments({});
    setProxyAction({ kind, title, accounts, loginFlow });
    setProxyActionError("");
    setProxyActionResult(null);
  }

  function prepareSecurityAction(action, jobs = selectedJobs, single = false) {
    if (batchAction) return;
    const permission = securityPermission(action);
    const accounts = jobs.map((job) => ({ key: job.id, email: job.email, currentEndpoint: job.proxyEndpoint || null, skipped: !job[permission] }));
    if (!accounts.some((account) => !account.skipped)) return;
    setSecurityUseStoredProxy(!defaultOperationProxy?.configured && accounts.every((account) => account.skipped || isSocks5ProxyUrl(account.currentEndpoint)));
    setActionProxyAssignments({});
    setProxyActionResult(null);
    setProxyActionError("");
    setSecurityChooser(null);
    setProxyAction({ kind: `security-${action}`, title: securityActionLabel(action), securityAction: action, single, accounts });
  }

  async function submitProxyAction(event) {
    event.preventDefault();
    if (!proxyAction || batchAction || proxyActionResult) return;
    setBatchAction(proxyAction.kind);
    try {
      const accounts = proxyAction.accounts.filter((account) => !account.skipped);
      if (proxyAction.securityAction) {
        if (securityProxyError) throw new Error(securityProxyError);
        const proxyAssignments = securityUseStoredProxy
          ? defaultOperationProxy?.configured ? accounts.map((account) => ({ id: account.key, proxyUrl: { useStoredProxy: true } })) : null
          : accounts.map((account) => ({ id: account.key, proxyUrl: selectedProxyUrl(actionProxyAssignments[account.key], securityProxies, defaultOperationProxy) }));
        const body = { action: proxyAction.securityAction };
        let url;
        if (proxyAction.single) {
          url = `/api/jobs/${accounts[0].key}/security`;
          if (proxyAssignments) body.proxyUrl = proxyAssignments[0].proxyUrl;
        } else {
          url = "/api/jobs/security/batch";
          body.ids = accounts.map((account) => account.key);
          if (proxyAssignments) body.proxyAssignments = proxyAssignments;
        }
        const data = await apiFetch(token, url, { method: "POST", body: JSON.stringify(body) });
        const started = proxyAction.single ? 1 : Number(data.started || 0);
        const skipped = proxyAction.accounts.length - accounts.length + Number(data.skipped || 0);
        const errors = data.errors || [];
        const results = proxyAction.single ? [{ id: accounts[0].key, email: accounts[0].email, status: "started" }] : [
          ...(data.results || []),
          ...proxyAction.accounts.filter((account) => account.skipped).map((account) => ({ id: account.key, email: account.email, status: "skipped", error: "本次不符合操作条件" })),
        ];
        setProxyActionResult({ started, skipped, errors, results });
        setUploadNotice(`${proxyAction.title}：已排队 ${started} 个，跳过 ${skipped} 个${errors.length ? `，失败 ${errors.length} 个` : ""}。执行结果可在账号详情查看。`);
        if (!proxyAction.single) setSelectedJobIds(new Set(results.filter((result) => result.status !== "started").map((result) => result.id)));
        setError("");
        return;
      }
      const proxyAssignments = accounts.map((account) => ({ id: account.key, proxyUrl: selectedProxyUrl(actionProxyAssignments[account.key], proxyState.proxies, defaultOperationProxy) }));
      const data = await apiFetch(token, `/api/jobs/${proxyAction.kind}-batch`, {
        method: "POST",
        body: JSON.stringify({ ids: accounts.map((account) => account.key), proxyAssignments, loginFlow: proxyAction.loginFlow || "codex" }),
      });
      const skipped = proxyAction.accounts.length - accounts.length + (data.skipped || 0);
      setUploadNotice(`已开始${proxyAction.title} ${data.started} 个账号${skipped ? `，跳过 ${skipped} 个` : ""}`);
      setSelectedJobIds(new Set());
      setProxyAction(null);
      setError("");
    } catch (requestError) {
      setProxyActionError(requestError.message);
    } finally {
      setBatchAction("");
    }
  }

  function reauthorizeSelected(loginFlow = "codex") {
    if (!canReauthorizeSelected || batchAction) return;
    prepareProxyAction("reauthorize", loginFlow === "legacy" ? "登录账号后授权 Codex" : "直接授权 Codex", () => true, loginFlow);
  }

  async function setupTotpSelected() {
    if (!canSetupTotpSelected || batchAction) return;
    const skipped = selectedJobIds.size - totpSetupSelectedCount;
    const message = `确定为选中的 ${totpSetupSelectedCount} 个账号设置 2FA 吗？${skipped ? `另有 ${skipped} 个账号不符合条件，将自动跳过。` : ""}`;
    if (!window.confirm(message)) return;
    prepareProxyAction("setup-2fa", "设置 2FA", (job) => job.canSetupTotp);
  }

  async function addPasswordSelected() {
    if (!canAddPasswordSelected || batchAction) return;
    const skipped = selectedJobIds.size - passwordAddSelectedCount;
    const message = `确定为选中的 ${passwordAddSelectedCount} 个无密码账号生成并添加随机强密码吗？${skipped ? `另有 ${skipped} 个账号已有密码或不符合条件，将自动跳过。` : ""}`;
    if (!window.confirm(message)) return;
    prepareProxyAction("add-password", "添加密码", (job) => job.canAddPassword);
  }

  async function forceReloginSelected(loginFlow = "codex") {
    if (!canForceReloginSelected || batchAction) return;
    const skipped = selectedJobIds.size - forceReloginSelectedCount;
    const message = `确定让选中的 ${forceReloginSelectedCount} 个账号跳过刷新令牌，重新登录并授权吗？${skipped ? `另有 ${skipped} 个进行中账号将自动跳过。` : ""}`;
    if (!window.confirm(message)) return;
    prepareProxyAction("relogin", loginFlow === "legacy" ? "重新登录并授权（旧）" : "重新登录并授权", (job) => job.canForceRelogin, loginFlow);
  }

  async function exportSelectedSource() {
    if (!selectedJobIds.size || batchAction) return;
    setBatchAction("source");
    try {
      const response = await fetch("/api/jobs/export-source", {
        method: "POST",
        headers: { "content-type": "application/json", "x-console-token": token },
        body: JSON.stringify({ ids: [...selectedJobIds] }),
      });
      if (!response.ok) throw new Error((await response.json()).error || "原始信息导出失败");
      await saveDownloadResponse(response, `chatgpt-account-source-${selectedJobIds.size}-accounts-${localTimestamp()}.txt`);
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBatchAction("");
    }
  }

  async function deleteSelected() {
    if (!selectedJobIds.size || batchAction) return;
    if (!window.confirm(`确定删除选中的 ${selectedJobIds.size} 条任务吗？对应的本地授权文件也会被删除。`)) return;
    setBatchAction("delete");
    try {
      await apiFetch(token, "/api/jobs/delete-batch", {
        method: "POST",
        body: JSON.stringify({ ids: [...selectedJobIds] }),
      });
      setJobs((current) => current.filter((job) => !selectedJobIds.has(job.id)));
      setSelectedJobIds(new Set());
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBatchAction("");
    }
  }

  async function cancelAllRunningJobs() {
    const runningCount = (stats.active || 0) + (stats.queued || 0);
    if (!runningCount || batchAction) return;
    if (!window.confirm(`确定停止全部 ${runningCount} 条进行中和排队任务吗？`)) return;
    setBatchAction("cancel-all");
    try {
      await apiFetch(token, "/api/jobs/cancel-all", { method: "POST" });
      setSelectedJobIds(new Set());
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBatchAction("");
    }
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <div className="brand-mark"><ShieldCheck size={21} strokeWidth={2.2} /></div>
          <div>
            <h1>ChatGPT 账号授权控制台</h1>
            <p>本地多任务协议登录</p>
          </div>
        </div>
        <div className="summary" aria-label="任务统计">
          <span><i className="status-dot active" />进行中 <strong>{stats.active}</strong></span>
          <span><i className="status-dot queued" />排队中 <strong>{stats.queued || 0}</strong></span>
          <span><i className="status-dot complete" />已完成 <strong>{stats.completed}</strong></span>
        </div>
      </header>

      <section className="workspace">
        {!settingsReady && (
          <div className={`connection-status ${initializationError ? "has-error" : ""}`} role={initializationError ? "alert" : "status"}>
            {initializationError ? <CircleAlert size={17} /> : <LoaderCircle className="spin" size={17} />}
            <span>{initializationError || "正在连接服务器并加载共享配置…"}</span>
            {initializationError && <button type="button" className="secondary-button" onClick={() => setInitializationAttempt((current) => current + 1)}><RefreshCw size={15} />重试连接</button>}
          </div>
        )}
        <div className="section-heading">
          <div>
            <h2>授权任务</h2>
            <p>{emailFilter.length || searchQuery
              ? `匹配 ${pagination.total} 条，共 ${pagination.totalAll ?? pagination.total} 条任务`
              : (pagination.total ? `共 ${pagination.total} 条任务` : "添加账号后可先保存资料，再选择操作")}</p>
          </div>
          <form className="add-form" onSubmit={createJob}>
            <button className="secondary-button scheduled-tasks-trigger" type="button" onClick={() => setScheduledTasksOpen(true)} disabled={!token || !settingsReady}>
              <CalendarClock size={17} />自动定时任务
            </button>
            <label className="add-mode-control"><span className="sr-only">添加方式</span><select aria-label="添加方式" value={addLoginMode} onChange={(event) => setAddLoginMode(event.target.value)} disabled={busy}><option value="save">仅保存账号，暂不上号</option><option value="login">添加并立即上号</option><option value="legacy">添加并立即上号（旧）</option></select></label>
            <AccountTermSelect value={accountTerm} onChange={setAccountTerm} label="新增账号类型" disabled={busy} className="add-account-term" />
            <div className="email-field">
              <Mail size={17} aria-hidden="true" />
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="输入邮箱地址"
                autoComplete="email"
                aria-label="邮箱地址"
                required
              />
            </div>
            <button className="primary-button" type="submit" disabled={!token || busy || (startLoginOnAdd && accountProxyUrl === null)} title={startLoginOnAdd && accountProxyUrl === null ? "请先选择登录代理或直连" : !startLoginOnAdd ? "仅记录账号，不登录、不授权、不推送；完整资料也可通过批量添加录入一个账号" : undefined}>
              {busy ? <LoaderCircle className="spin" size={17} /> : <Plus size={17} />}
              {startLoginOnAdd ? "添加并上号" : "保存账号"}
            </button>
            <button className="secondary-button" type="button" onClick={() => { setBatchError(""); setBatchPreview(null); setBatchProxyAssignments({}); setBatchAccountTerms({}); setBatchOpen(true); }} disabled={!token}>
              <ListPlus size={17} />
              批量添加
            </button>
            <button
              className={`secondary-button ${emailFilter.length ? "filter-active" : ""}`}
              type="button"
              onClick={() => { setFilterError(""); setFilterText(emailFilter.join("\n")); setFilterOpen(true); }}
              disabled={!token}
            >
              <Filter size={17} />
              {emailFilter.length ? `筛选 ${emailFilter.length}` : "筛选账号"}
            </button>
            {emailFilter.length > 0 && (
              <button className="selection-text-button clear-filter-button" type="button" onClick={clearEmailFilter}>
                清除筛选
              </button>
            )}
          </form>
        </div>

        <details className="configuration-panel" open>
          <summary><Settings2 size={15} /><strong>服务配置</strong><span>接码 · 邮件 · CRS · Sub2API</span><ChevronDown size={15} /></summary>
        <div className="integration-grid">
        <div className="provider-toolbar sms-provider-toolbar" aria-label="接码平台配置">
          <div className="provider-heading"><PhoneIncoming size={17} /><strong>接码平台</strong></div>
          <span className="provider-name">{activeSmsProvider.name || "未选择"}</span>
          <span className={`provider-ready ${activeSmsProvider.ready ? "" : "incomplete"}`}>
            {activeSmsProvider.ready ? <Check size={14} /> : <CircleAlert size={14} />}
            {activeSmsProvider.ready
              ? (activeSmsProvider.summary ? `已配置 · ${activeSmsProvider.summary}` : "已配置")
              : "未完成配置"}
          </span>
          <button type="button" className="secondary-button provider-settings-button" onClick={openSmsSettings} disabled={!settingsReady || !smsProviderDefinitions.length}>
            <Settings2 size={16} />配置
          </button>
        </div>

        <div className="provider-toolbar mail-request-toolbar" aria-label="邮件接码请求配置">
          <div className="provider-heading"><MailCheck size={17} /><strong>邮件 API</strong></div>
          <span className="provider-name">{mailRequestSettings.method}</span>
          <span className="provider-ready">
            <Check size={14} />
            {formatMailRequestSummary(mailRequestSettings)}
          </span>
          <button type="button" className="secondary-button provider-settings-button" onClick={openMailRequestSettings} disabled={!token}>
            <Settings2 size={16} />配置
          </button>
        </div>

        <CrsToolbar crs={crs} />

        <div className="provider-toolbar sub2api-toolbar" aria-label="Sub2API 配置与号池监控">
          <div className="provider-heading"><Send size={17} /><strong>Sub2API</strong></div>
          <span className="provider-name">{sub2apiSettings.baseUrl || "未配置后端"}</span>
          <span className={`provider-ready ${sub2apiSettings.adminApiKey ? "" : "incomplete"}`}>
            {sub2apiSettings.adminApiKey ? <Check size={14} /> : <CircleAlert size={14} />}
            {sub2apiSettings.adminApiKey
              ? `${sub2apiSettings.groupIds.length ? `已配置 · ${sub2apiSettings.groupIds.length} 个号池` : "已配置 · 默认号池"}${sub2apiSettings.proxyId ? " · 已指定代理" : ""}`
              : "未完成配置"}
          </span>
          {features.sub2apiMonitor && (
            <span className={`provider-ready monitor-ready ${sub2apiMonitorStatus.enabled ? "" : "incomplete"}`}>
              {sub2apiMonitorStatus.running
                ? <LoaderCircle className="spin" size={14} />
                : sub2apiMonitorStatus.enabled ? <ShieldCheck size={14} /> : <CircleAlert size={14} />}
              {sub2apiMonitorStatus.running
                ? "正在巡检"
                : sub2apiMonitorStatus.enabled
                  ? `号池监控已启用${sub2apiMonitorStatus.lastCheckAt ? ` · ${formatRelativeMonitorTime(sub2apiMonitorStatus.lastCheckAt)}` : ""}`
                  : "号池监控未启用"}
            </span>
          )}
          {features.sub2apiMonitor && sub2apiMonitorStatus.enabled && (
            <button
              type="button"
              className="icon-button monitor-check-button"
              onClick={checkSub2ApiMonitorNow}
              disabled={sub2apiMonitorChecking || sub2apiMonitorStatus.running}
              title="立即检查 Sub2API 异常账号"
            >
              <RefreshCw className={sub2apiMonitorChecking || sub2apiMonitorStatus.running ? "spin" : ""} size={16} />
            </button>
          )}
          <button type="button" className="secondary-button provider-settings-button" onClick={openSub2ApiSettings} disabled={!token}>
            <Settings2 size={16} />配置
          </button>
        </div>

        </div>
        </details>

        <div className="provider-toolbar account-proxy-toolbar" aria-label="登录代理配置">
          <div className="provider-heading"><Globe2 size={17} /><strong>登录代理</strong></div>
          <div className="account-proxy-input">
            <ProxySelect proxies={proxyState.proxies} value={selectedOperationProxyId} onChange={saveProxySelection} label="单个任务登录代理" defaultOperationProxy={defaultOperationProxy} disabled={!settingsReady || Boolean(settingsSavingSection)} />
          </div>
          <span className={`provider-ready ${accountProxyUrl === null ? "incomplete" : ""}`}>
            {accountProxyUrl === null ? <CircleAlert size={14} /> : <Check size={14} />}
            {accountProxyUrl === null ? "请选择代理或直连" : selectedOperationProxyId === DEFAULT_OPERATION_PROXY_ID ? defaultOperationProxy?.label || "默认美国动态住宅代理" : selectedProxy ? "单个任务使用此代理" : "单个任务使用直连"}
          </span>
          <button type="button" className="secondary-button proxy-manager-button" onClick={() => setProxyManagerOpen(true)} disabled={!settingsReady || Boolean(settingsSavingSection)}><Settings2 size={16} />管理代理{proxyState.proxies.length ? ` · ${proxyState.proxies.length}` : ""}</button>
          <span className="proxy-toolbar-note">批量登录时逐个账号选择</span>

        </div>

        {settingsError && (
          <div className="global-error" role="alert">
            <CircleAlert size={17} /><span>{settingsError}</span>
            <button type="button" onClick={() => setInitializationAttempt((current) => current + 1)}>重新连接</button>
            <button type="button" onClick={() => setSettingsError("")} title="关闭配置提示"><X size={16} /></button>
          </div>
        )}
        {error && (
          <div className="global-error" role="alert">
            <CircleAlert size={17} />
            <span>{error}</span>
            <button type="button" onClick={() => setError("")} title="关闭"><X size={16} /></button>
          </div>
        )}
        {uploadNotice && (
          <div className="global-success" role="status">
            <Check size={17} />
            <span>{uploadNotice}</span>
            <button type="button" onClick={() => setUploadNotice("")} title="关闭"><X size={16} /></button>
          </div>
        )}

        <AccountAreaTabs area={accountArea} counts={areaCounts} onChange={changeAccountArea} disabled={!token} />
        {accountArea === "resting" && <p className="resting-area-hint">已执行退出其他设备的账号集中在此；重新登录并授权成功后自动移出。退出时长从登出请求开始计算。</p>}
        {accountArea === "retired" && <p className="retired-area-hint">上游已删除、永久禁用或已明确标记作废的账号集中在此。</p>}

        <div className="account-list-toolbar">
          <div className="account-search">
            <Search size={16} aria-hidden="true" />
            <input type="search" maxLength={200} value={accountSearch} onChange={(event) => setAccountSearch(event.target.value)} placeholder="搜索邮箱 / 任务 ID" aria-label="搜索账号" autoComplete="off" disabled={!token} />
            {accountSearch && <button type="button" aria-label="清空搜索" onClick={() => setAccountSearch("")}><X size={14} /></button>}
          </div>
          <span className="account-list-count" role="status">{searchQuery || emailFilter.length ? `匹配 ${pagination.total} / ${pagination.totalAll ?? pagination.total} 个账号` : `共 ${pagination.total} 个账号`}<span>每页 {pagination.pageSize} 条</span></span>
        </div>

        {features.bulkActions && (jobs.length > 0 || selectedJobIds.size > 0) && (
          <div className="selection-toolbar">
            <div className="selection-summary">
              <span>当前页 {jobs.length} 条，跨页已选 {selectedJobIds.size} 条，可下载 {downloadableSelectedCount} 条</span>
              <button type="button" className="selection-text-button" onClick={toggleAllOnPage} disabled={allPageSelected || !pageJobIds.length}>
                本页全选
              </button>
              <button type="button" className="selection-text-button" onClick={() => setSelectedJobIds(new Set())} disabled={!selectedJobIds.size}>
                清除选择
              </button>
            </div>
            <div className="bulk-actions">
              {features.cancelAll && (
                <button
                  type="button"
                  className="stop-all-button"
                  onClick={cancelAllRunningJobs}
                  disabled={!(stats.active || stats.queued) || Boolean(batchAction)}
                >
                  {batchAction === "cancel-all" ? <LoaderCircle className="spin" size={16} /> : <Ban size={16} />}
                  停止全部
                </button>
              )}
              <button type="button" className="download-button" onClick={downloadSelected} disabled={!canDownloadSelected || Boolean(batchAction)}>
                {batchAction === "download" ? <LoaderCircle className="spin" size={16} /> : <Download size={16} />}
                批量下载
              </button>
              <CrsBatchSettingsButton crs={crs} jobs={selectedJobs} />
              <button type="button" className="secondary-button bulk-button" onClick={() => moveSelectedAccounts("rest")} disabled={!selectedJobs.length || Boolean(batchAction)}>移到静置区</button>
              <button type="button" className="secondary-button bulk-button" onClick={() => moveSelectedAccounts("retire")} disabled={!selectedJobs.length || Boolean(batchAction)}>移到废号区</button>
              <CrsUploadButton crs={crs} jobs={selectedJobs} disabled={Boolean(batchAction)} />
              {features.sub2apiUpload && (
                <button type="button" className="secondary-button bulk-button" onClick={() => uploadSelected([...selectedJobIds])} disabled={!canUploadSelected || Boolean(batchAction)}>
                  {batchAction === "upload" ? <LoaderCircle className="spin" size={16} /> : <Send size={16} />}
                  上传到 Sub2API
                </button>
              )}
              {features.sourceExport && (
                <button type="button" className="secondary-button bulk-button" onClick={exportSelectedSource} disabled={!selectedJobIds.size || Boolean(batchAction)}>
                  {batchAction === "source" ? <LoaderCircle className="spin" size={16} /> : <FileText size={16} />}
                  导出原始信息
                </button>
              )}
              <button type="button" className="regenerate-button bulk-button" onClick={() => reauthorizeSelected()} disabled={!canReauthorizeSelected || Boolean(batchAction)}>
                {batchAction === "reauthorize" ? <LoaderCircle className="spin" size={16} /> : <RefreshCw size={16} />}
                批量直接授权 Codex
              </button>
              <button type="button" className="regenerate-button bulk-button" onClick={() => reauthorizeSelected("legacy")} disabled={!canReauthorizeSelected || Boolean(batchAction)} title="优先刷新授权；失效后先登录网页再完成 Codex 授权">
                <RefreshCw size={16} />批量登录账号后授权 Codex
              </button>
              {features.forceRelogin && (
                <button type="button" className="relogin-button bulk-button" onClick={() => forceReloginSelected()} disabled={!canForceReloginSelected || Boolean(batchAction)}>
                  {batchAction === "relogin" ? <LoaderCircle className="spin" size={16} /> : <LogIn size={16} />}
                  批量重新登录
                </button>
              )}
              {features.forceRelogin && (
                <button type="button" className="relogin-button bulk-button" onClick={() => forceReloginSelected("legacy")} disabled={!canForceReloginSelected || Boolean(batchAction)} title="先登录网页再完成 Codex 授权">
                  <LogIn size={16} />批量重新登录（旧）
                </button>
              )}
              {features.totpSetup && (
                <button type="button" className="secondary-button bulk-button" onClick={setupTotpSelected} disabled={!canSetupTotpSelected || Boolean(batchAction)}>
                  {batchAction === "setup-2fa" ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />}
                  批量设置 2FA
                </button>
              )}
              <div className="security-toolbar-group" aria-label="批量账号安全操作">
                <button type="button" className="secondary-button bulk-button account-security-button" onClick={() => setSecurityChooser({ jobs: selectedJobs, single: false })} disabled={!canSecuritySelected || Boolean(batchAction)}><ShieldCheck size={16} />批量账号安全<ChevronDown size={14} /></button>
              </div>
              {features.passwordAdd && (
                <button type="button" className="secondary-button bulk-button" onClick={addPasswordSelected} disabled={!canAddPasswordSelected || Boolean(batchAction)}>
                  {batchAction === "add-password" ? <LoaderCircle className="spin" size={16} /> : <KeyRound size={16} />}
                  批量添加密码
                </button>
              )}
              <button type="button" className="delete-button" onClick={deleteSelected} disabled={!selectedJobIds.size || Boolean(batchAction)}>
                {batchAction === "delete" ? <LoaderCircle className="spin" size={16} /> : <Trash2 size={16} />}
                批量删除
              </button>
            </div>
          </div>
        )}

        <div className="table-frame">
          <table className="jobs-table">
            <thead>
              <tr>
                <th className="select-heading">
                  <input
                    type="checkbox"
                    checked={allPageSelected}
                    onChange={toggleAllOnPage}
                    disabled={!features.bulkActions || !pageJobIds.length}
                    aria-label="选择当前页全部任务"
                  />
                </th>
                <th>账号</th>
                <th>CRS 设置</th>
                <th>状态</th>
                <th>当前操作</th>
                <th>开始时间</th>
                <th>最近操作时间</th>
                <th className="actions-heading">操作</th>
              </tr>
            </thead>
            <tbody>
              {!jobs.length && <EmptyState filtered={emailFilter.length > 0 || Boolean(searchQuery)} area={accountArea} />}
              {jobs.map((job) => (
                <React.Fragment key={job.id}>
                  <JobRow
                    job={job}
                    crs={crs}
                    token={token}
                    expanded={expandedJobId === job.id}
                    onToggleLogs={() => setExpandedJobId((current) => current === job.id ? null : job.id)}
                    onError={setError}
                    onUpdateAccountTerm={updateAccountTerm}
                    selected={selectedJobIds.has(job.id)}
                    onToggleSelected={() => toggleJobSelection(job.id)}
                    selectionSupported={Boolean(features.bulkActions)}
                    smsProviderAvailable={smsProviderDefinitions.length > 0}
                    smsProvider={activeSmsProvider}
                    onUpload={() => uploadSelected([job.id])}
                    sub2apiUploadAvailable={Boolean(features.sub2apiUpload && sub2apiSettings.baseUrl && sub2apiSettings.adminApiKey)}
                    totpSetupAvailable={Boolean(features.totpSetup)}
                    passwordAddAvailable={Boolean(features.passwordAdd)}
                    forceReloginAvailable={Boolean(features.forceRelogin)}
                    accountProxyUrl={accountProxyUrl}
                    onChangeProxy={() => { setProxyChange(job); setProxyChangeId(""); setProxyChangeError(""); }}
                    onSecurityAction={() => setSecurityChooser({ jobs: [job], single: true })}
                  />
                  {expandedJobId === job.id && (
                    <tr className="log-row">
                      <td colSpan="8"><JobLogs token={token} jobId={job.id} /></td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
        {features.pagination && (
          <nav className="pagination" aria-label="任务分页">
            <span className="pagination-range">{pagination.total ? `${(pagination.page - 1) * pagination.pageSize + 1}–${Math.min(pagination.page * pagination.pageSize, pagination.total)}` : "0"} / 共 {pagination.total} 条</span>
            <div className="pagination-pages">
            <button type="button" className="icon-button" onClick={() => setPage((current) => Math.max(1, current - 1))} disabled={page <= 1} title="上一页" aria-label="上一页">
              <ChevronLeft size={17} />
            </button>
            {paginationItems(pagination.page, pagination.totalPages).map((item) => typeof item === "number"
              ? <button type="button" className={`page-button ${item === pagination.page ? "is-current" : ""}`} key={item} aria-label={`第 ${item} 页`} aria-current={item === pagination.page ? "page" : undefined} onClick={() => setPage(item)}>{item}</button>
              : <span className="pagination-ellipsis" key={item} aria-hidden="true">…</span>)}
            <button type="button" className="icon-button" onClick={() => setPage((current) => Math.min(pagination.totalPages, current + 1))} disabled={page >= pagination.totalPages} title="下一页" aria-label="下一页">
              <ChevronRight size={17} />
            </button>
            </div>
            <span className="pagination-total">共 {pagination.totalPages} 页</span>
          </nav>
        )}
      </section>
      {smsSettingsOpen && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => {
          if (event.target === event.currentTarget && !smsSettingsSaving) setSmsSettingsOpen(false);
        }}>
          <form className="batch-dialog sms-settings-dialog" onSubmit={saveSmsSettings} role="dialog" aria-modal="true" aria-labelledby="sms-settings-title">
            <div className="dialog-header">
              <div>
                <h2 id="sms-settings-title">接码平台配置</h2>
                <span>配置保存在服务器，不同电脑共用</span>
              </div>
              <button type="button" className="icon-button" onClick={() => setSmsSettingsOpen(false)} disabled={smsSettingsSaving} title="关闭">
                <X size={18} />
              </button>
            </div>

            <div className="provider-tabs" role="tablist" aria-label="选择接码平台">
              {smsProviderDefinitions.map((provider) => (
                <button
                  key={provider.id}
                  type="button"
                  role="tab"
                  aria-selected={draftSmsProvider.id === provider.id}
                  className={draftSmsProvider.id === provider.id ? "active" : ""}
                  onClick={() => {
                    setSmsSettingsDraft((current) => withSmsProviderDefaults(smsProviderDefinitions, {
                      ...current,
                      selectedProviderId: provider.id,
                    }));
                    setSmsSettingsError("");
                  }}
                >
                  {provider.name}
                </button>
              ))}
            </div>

            {draftSmsProvider.definition && (
              <div className="provider-config-section">
                <div className="provider-description-row">
                  <div className="provider-description">{draftSmsProvider.definition.description}</div>
                  {SMS_PROVIDER_EXTERNAL_LINKS[draftSmsProvider.id] && (
                    <a
                      className="provider-external-link"
                      href={SMS_PROVIDER_EXTERNAL_LINKS[draftSmsProvider.id].href}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <ExternalLink size={13} aria-hidden="true" />
                      {SMS_PROVIDER_EXTERNAL_LINKS[draftSmsProvider.id].label}
                    </a>
                  )}
                </div>
                <div className="provider-config-grid">
                  {draftSmsProvider.definition.fields.filter((field) => field.type !== "hidden").map((field) => (
                    <label key={field.key} className={`settings-field ${["price-select", "textarea"].includes(field.type) ? "wide-settings-field" : ""}`}>
                      <span>{field.label}</span>
                      {field.type === "price-select" ? (
                        <div className="price-select-row">
                          <div className="price-select-box">
                            <Settings2 size={15} />
                            <select
                              value={draftSmsProvider.config.country || ""}
                              onChange={(event) => {
                                const selected = smsNumberOptions.find((option) => option.country === event.target.value);
                                if (!selected) return;
                                updateSmsProviderConfig(draftSmsProvider.id, {
                                  country: selected.country,
                                  maxPrice: String(selected.price),
                                  countryLabel: formatSmsCountryName(selected),
                                });
                              }}
                              disabled={!smsNumberOptions.length || smsOptionsLoading}
                              aria-label="SMSBower 国家与价格"
                            >
                              {!smsNumberOptions.length && (
                                <option value={draftSmsProvider.config.country || ""}>
                                  {smsOptionsLoading ? "正在查询实时价格..." : "请先查询实时价格"}
                                </option>
                              )}
                              {smsNumberOptions.map((option) => (
                                <option key={option.country} value={option.country}>{formatSmsPriceOption(option)}</option>
                              ))}
                            </select>
                          </div>
                          <button
                            type="button"
                            className="price-refresh-button"
                            onClick={() => loadSmsNumberOptions()}
                            disabled={smsOptionsLoading || !draftSmsProvider.config.apiKey}
                          >
                            {smsOptionsLoading ? <LoaderCircle className="spin" size={15} /> : <RefreshCw size={15} />}
                            {smsOptionsLoading ? "查询中" : "查询价格"}
                          </button>
                        </div>
                      ) : field.type === "textarea" ? (
                        <textarea
                          className="settings-textarea"
                          value={draftSmsProvider.config[field.key] || ""}
                          onChange={(event) => updateSmsProviderConfig(draftSmsProvider.id, { [field.key]: event.target.value })}
                          placeholder={field.placeholder}
                          rows="8"
                          autoComplete="off"
                          spellCheck="false"
                        />
                      ) : (
                        <div>
                          {field.type === "password" ? <KeyRound size={15} /> : <Settings2 size={15} />}
                          <input
                            type={field.type || "text"}
                            value={draftSmsProvider.config[field.key] || ""}
                            onChange={(event) => updateSmsProviderConfig(draftSmsProvider.id, { [field.key]: event.target.value })}
                            placeholder={field.placeholder}
                            autoComplete="off"
                            spellCheck="false"
                          />
                        </div>
                      )}
                    </label>
                  ))}
                </div>
              </div>
            )}

            {smsSettingsError && <div className="dialog-error" role="alert"><CircleAlert size={15} />{smsSettingsError}</div>}
            <div className="dialog-footer">
              <button type="button" className="cancel-button" onClick={() => setSmsSettingsOpen(false)} disabled={smsSettingsSaving}>取消</button>
              <button type="submit" className="primary-button" disabled={!draftSmsProvider.definition || smsSettingsSaving}>
                {smsSettingsSaving ? <LoaderCircle className="spin" size={17} /> : <Check size={17} />}{smsSettingsSaving ? "正在保存…" : "保存配置"}
              </button>
            </div>
          </form>
        </div>
      )}
      {mailRequestSettingsOpen && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => {
          if (event.target === event.currentTarget && !mailRequestSettingsSaving) setMailRequestSettingsOpen(false);
        }}>
          <form className="batch-dialog mail-request-settings-dialog" onSubmit={saveMailRequestSettings} role="dialog" aria-modal="true" aria-labelledby="mail-request-settings-title">
            <div className="dialog-header">
              <div>
                <h2 id="mail-request-settings-title">邮件 API 请求配置</h2>
                <span>配置保存在服务器，请求内容不会写入任务日志</span>
              </div>
              <button type="button" className="icon-button" onClick={() => setMailRequestSettingsOpen(false)} disabled={mailRequestSettingsSaving} title="关闭">
                <X size={18} />
              </button>
            </div>

            <div className="provider-tabs mail-method-tabs" role="tablist" aria-label="邮件 API 请求方式">
              {["GET", "POST"].map((method) => (
                <button
                  key={method}
                  type="button"
                  role="tab"
                  aria-selected={mailRequestSettingsDraft.method === method}
                  className={mailRequestSettingsDraft.method === method ? "active" : ""}
                  onClick={() => setMailRequestSettingsDraft((current) => ({ ...current, method }))}
                >
                  {method}
                </button>
              ))}
            </div>

            <div className="provider-config-grid mail-request-config-grid">
              {mailRequestSettingsDraft.method === "POST" && (
                <label className="settings-field wide-settings-field">
                  <span className="mail-request-url-label">
                    统一 POST 请求 URL
                    <small>必填</small>
                  </span>
                  <input
                    className="mail-request-url-input"
                    type="url"
                    value={mailRequestSettingsDraft.url}
                    onChange={(event) => setMailRequestSettingsDraft((current) => ({ ...current, url: event.target.value }))}
                    placeholder="https://mail.example/api/messages"
                    autoComplete="off"
                    spellCheck="false"
                  />
                  <small>每个账号自己的请求体请在批量添加账号时一并导入</small>
                </label>
              )}
              <label className="settings-field wide-settings-field">
                <span>请求头 JSON</span>
                <textarea
                  className="settings-textarea"
                  value={mailRequestSettingsDraft.headersText}
                  onChange={(event) => setMailRequestSettingsDraft((current) => ({ ...current, headersText: event.target.value }))}
                  placeholder={'{"Authorization":"Bearer ...","Referer":"https://mail.example/"}'}
                  rows="7"
                  autoComplete="off"
                  spellCheck="false"
                />
              </label>
            </div>

            {mailRequestSettingsError && <div className="dialog-error" role="alert"><CircleAlert size={15} />{mailRequestSettingsError}</div>}
            <div className="dialog-footer">
              <button type="button" className="cancel-button" onClick={() => setMailRequestSettingsOpen(false)} disabled={mailRequestSettingsSaving}>取消</button>
              <button type="submit" className="primary-button" disabled={mailRequestSettingsSaving || !token}>
                {mailRequestSettingsSaving ? <LoaderCircle className="spin" size={17} /> : <Check size={17} />}
                保存配置
              </button>
            </div>
          </form>
        </div>
      )}
      {sub2apiSettingsOpen && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => {
          if (event.target === event.currentTarget) setSub2apiSettingsOpen(false);
        }}>
          <form className="batch-dialog sub2api-settings-dialog" onSubmit={saveSub2ApiSettings} role="dialog" aria-modal="true" aria-labelledby="sub2api-settings-title">
            <div className="dialog-header">
              <div>
                <h2 id="sub2api-settings-title">Sub2API 配置</h2>
                <span>管理员 Key 不写入任务文件或日志；启用监控后由本机服务保存</span>
              </div>
              <button type="button" className="icon-button" onClick={() => setSub2apiSettingsOpen(false)} title="关闭"><X size={18} /></button>
            </div>
            <div className="provider-config-grid sub2api-config-grid">
              <label className="settings-field wide-settings-field">
                <span>Sub2API 后端地址</span>
                <input
                  type="url"
                  value={sub2apiSettingsDraft.baseUrl}
                  onChange={(event) => setSub2apiSettingsDraft((current) => ({ ...current, baseUrl: event.target.value }))}
                  placeholder="例如 http://127.0.0.1:8080"
                  autoComplete="url"
                />
              </label>
              {features.sub2apiMonitor && (
                <label className="settings-field wide-settings-field sub2api-monitor-toggle">
                  <input
                    type="checkbox"
                    checked={Boolean(sub2apiSettingsDraft.monitorEnabled)}
                    onChange={(event) => setSub2apiSettingsDraft((current) => ({ ...current, monitorEnabled: event.target.checked }))}
                  />
                  <span>
                    <strong>每 5 分钟监控异常账号</strong>
                    <small>只自动处理上次完整登录未人工输入密码、邮箱码或登录 2FA 的任务</small>
                  </span>
                </label>
              )}
              <label className="settings-field wide-settings-field">
                <span>管理员 API Key</span>
                <input
                  type="password"
                  value={sub2apiSettingsDraft.adminApiKey}
                  onChange={(event) => setSub2apiSettingsDraft((current) => ({ ...current, adminApiKey: event.target.value }))}
                  placeholder="输入 sub2api 管理员 API Key"
                  autoComplete="off"
                />
              </label>
              <fieldset className="settings-field wide-settings-field sub2api-group-field">
                <legend>目标号池（可多选）</legend>
                <section className="sub2api-group-picker" aria-label="目标号池">
                  {sub2apiGroups.length ? sub2apiGroups.map((group) => {
                    const groupId = String(group.id);
                    return (
                      <label key={group.id} className="sub2api-group-option">
                        <input
                          type="checkbox"
                          checked={sub2apiSettingsDraft.groupIds.includes(groupId)}
                          onChange={(event) => setSub2ApiGroupChecked(groupId, event.target.checked)}
                        />
                        <span>{group.name}</span>
                        <small>ID: {group.id}</small>
                      </label>
                    );
                  }) : <div className="sub2api-group-empty">暂无可选号池</div>}
                </section>
                <section className="sub2api-group-selection" aria-label="号池选择操作">
                  <span>已选 {sub2apiSettingsDraft.groupIds.length} 个</span>
                  <button
                    type="button"
                    onClick={() => setSub2apiSettingsDraft((current) => ({ ...current, groupIds: sub2apiGroups.map((group) => String(group.id)) }))}
                    disabled={!sub2apiGroups.length || sub2apiGroups.every((group) => sub2apiSettingsDraft.groupIds.includes(String(group.id)))}
                  >
                    全选
                  </button>
                  <button
                    type="button"
                    onClick={() => setSub2apiSettingsDraft((current) => ({ ...current, groupIds: [] }))}
                    disabled={!sub2apiSettingsDraft.groupIds.length}
                  >
                    清空
                  </button>
                </section>
              </fieldset>
              <label className="settings-field wide-settings-field">
                <span>代理 IP</span>
                <select
                  value={sub2apiSettingsDraft.proxyId}
                  onChange={(event) => setSub2apiSettingsDraft((current) => ({ ...current, proxyId: event.target.value }))}
                >
                  <option value="">使用账号原配置</option>
                  {sub2apiProxies.map((proxy) => <option key={proxy.id} value={String(proxy.id)}>{formatSub2ApiProxy(proxy)}</option>)}
                </select>
              </label>
              <label className="settings-field wide-settings-field">
                <span>Codex 指纹收敛</span>
                <select
                  value={sub2apiSettingsDraft.codexFingerprintMode}
                  onChange={(event) => setSub2apiSettingsDraft((current) => ({ ...current, codexFingerprintMode: event.target.value }))}
                >
                  <option value="off">关闭（透传）</option>
                  <option value="device">仅设备</option>
                  <option value="session">设备+会话（推荐）</option>
                  <option value="full">完全收敛</option>
                </select>
              </label>
              <label className="settings-field">
                <span>账号并发</span>
                <input
                  type="number"
                  min="0"
                  max="10000"
                  step="1"
                  value={sub2apiSettingsDraft.concurrency}
                  onChange={(event) => setSub2apiSettingsDraft((current) => ({ ...current, concurrency: event.target.value }))}
                  placeholder="留空使用账号原值"
                />
              </label>
              <label className="settings-field">
                <span>负载因子</span>
                <input
                  type="number"
                  min="0"
                  max="10000"
                  step="1"
                  value={sub2apiSettingsDraft.loadFactor}
                  onChange={(event) => setSub2apiSettingsDraft((current) => ({ ...current, loadFactor: event.target.value }))}
                  placeholder="留空使用账号原值"
                />
              </label>
              <label className="settings-field">
                <span>账号优先级</span>
                <input
                  type="number"
                  min="0"
                  max="10000"
                  step="1"
                  value={sub2apiSettingsDraft.priority}
                  onChange={(event) => setSub2apiSettingsDraft((current) => ({ ...current, priority: event.target.value }))}
                  placeholder="留空使用账号原值"
                />
              </label>
              <label className="settings-field wide-settings-field">
                <span>允许使用的模型</span>
                <textarea
                  className="sub2api-model-textarea"
                  value={sub2apiSettingsDraft.modelWhitelist}
                  onChange={(event) => setSub2apiSettingsDraft((current) => ({ ...current, modelWhitelist: event.target.value }))}
                  placeholder={"每行一个模型，也支持逗号分隔，例如：\ngpt-5\ngpt-5-mini\ngpt-4.1"}
                  rows="5"
                  spellCheck="false"
                />
              </label>
            </div>
            <div className="dialog-hint">分组为空时，上传使用 Sub2API 默认号池，监控检查全部 OpenAI 账号；选择分组后只监控这些号池。Codex 指纹收敛会写入每个上传或巡检更新的 OpenAI OAuth 账号。</div>
            {features.sub2apiMonitor && sub2apiMonitorStatus.configured && (
              <div className={`sub2api-monitor-status ${sub2apiMonitorStatus.lastError ? "error" : ""}`}>
                <ShieldCheck size={15} />
                <span>{sub2apiMonitorStatus.lastError
                  ? `上次巡检失败：${sub2apiMonitorStatus.lastError}`
                  : sub2apiMonitorStatus.lastCheckAt
                    ? formatMonitorResult(sub2apiMonitorStatus.lastResult)
                    : "尚未执行号池巡检"}</span>
              </div>
            )}
            {sub2apiSettingsError && <div className="dialog-error" role="alert"><CircleAlert size={15} />{sub2apiSettingsError}</div>}
            <div className="dialog-actions sub2api-dialog-actions">
              <button type="button" className="secondary-button" onClick={() => loadSub2ApiOptions()} disabled={sub2apiGroupsLoading || !token}>
                {sub2apiGroupsLoading ? <LoaderCircle className="spin" size={16} /> : <RotateCcw size={16} />}读取配置
              </button>
              {features.sub2apiMonitor && sub2apiMonitorStatus.enabled && (
                <button type="button" className="secondary-button" onClick={checkSub2ApiMonitorNow} disabled={sub2apiMonitorChecking || sub2apiMonitorStatus.running}>
                  {sub2apiMonitorChecking || sub2apiMonitorStatus.running ? <LoaderCircle className="spin" size={16} /> : <RefreshCw size={16} />}立即检查
                </button>
              )}
              <span className="dialog-actions-spacer" />
              <button type="button" className="cancel-button" onClick={() => setSub2apiSettingsOpen(false)} disabled={sub2apiSettingsSaving}>取消</button>
              <button type="submit" className="primary-button" disabled={sub2apiSettingsSaving}>
                {sub2apiSettingsSaving ? <LoaderCircle className="spin" size={16} /> : <Check size={16} />}保存配置
              </button>
            </div>
          </form>
        </div>
      )}
      {scheduledTasksOpen && <ScheduledTasksDialog request={dynamicProxyRequest} defaultOperationProxy={defaultOperationProxy} proxyState={proxyState} mailMethod={mailRequestSettings.method} cprConfigured={crs.status.configured} onManageProxies={() => setProxyManagerOpen(true)} onClose={() => setScheduledTasksOpen(false)} />}
      {batchOpen && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => {
          if (event.target === event.currentTarget && !batchBusy) setBatchOpen(false);
        }}>
          <form className="batch-dialog" onSubmit={createBatch} role="dialog" aria-modal="true" aria-labelledby="batch-title">
            <div className="dialog-header">
              <div>
                <h2 id="batch-title">批量添加账号</h2>
                <span>{countBatchLines(batchText)} 条 · {startLoginOnAdd ? "超出并发上限后自动排队" : "仅保存资料，不登录、不推送"}</span>
              </div>
              <button type="button" className="icon-button" onClick={() => setBatchOpen(false)} disabled={batchBusy} title="关闭">
                <X size={18} />
              </button>
            </div>
            <label className="batch-add-mode"><span>添加后如何处理</span><select aria-label="批量添加方式" value={addLoginMode} onChange={(event) => setAddLoginMode(event.target.value)} disabled={batchBusy}><option value="save">仅保存账号，暂不上号</option><option value="login">添加并立即上号</option><option value="legacy">添加并立即上号（旧）</option></select></label>
            <div className="batch-term-default"><span>账号类型</span><AccountTermSelect value={batchAccountTerm} onChange={(value) => { setBatchAccountTerm(value); setBatchAccountTerms({}); }} label="批量账号默认类型" disabled={batchBusy} /><small>预览后可为每个账号单独修改</small></div>
            {!startLoginOnAdd && <p className="save-only-hint">支持一个或多个账号。先记录资料，之后可单独更换 2FA；需要上号时再手动执行或创建定时任务。代理可在后续操作时选择。</p>}
            {!batchPreview && <label className="batch-label" htmlFor="batch-input">
              {mailRequestSettings.method === "POST"
                ? "每行：邮箱----编码请求体，或 邮箱----密码----编码请求体；邮箱及可识别字段顺序不限"
                : "每行一个账号：自动识别邮箱、密码、邮件 API 和 2FA，字段顺序不限"}
            </label>}
            {!batchPreview && <textarea
              id="batch-input"
              value={batchText}
              onChange={(event) => { setBatchText(event.target.value); setBatchPreview(null); setBatchProxyAssignments({}); }}
              placeholder={mailRequestSettings.method === "POST"
                ? "a@example.com----eyJtYWlsYm94X2lkIjoiaWQtYSJ9\nb@example.com----账号密码----mailbox_id%3Did-b"
                : "name@icloud.com----https://mail.example/messages/name\nhttps://mail.example/messages/name2|账号密码|name2@example.co.uk|BASE32二步验证密钥\nBASE32二步验证密钥::name3@example.dev::账号密码"}
              spellCheck="false"
              disabled={batchBusy}
              autoFocus
            />}
            {batchPreview && <><div className="proxy-batch-summary"><Check size={16} /><span>已识别 {batchPreview.length} 个账号，请核对类型{startLoginOnAdd ? "并选择各自的登录代理。" : "；将仅保存资料，不启动登录或推送。"}</span><button type="button" className="selection-text-button" disabled={batchBusy} onClick={() => { setBatchPreview(null); setBatchProxyAssignments({}); setBatchAccountTerms({}); setBatchError(""); }}>修改账号</button></div><ul className="batch-term-preview save-only-preview" aria-label="待添加账号类型">{batchPreview.map((account) => <li key={account.key}><Mail size={15} /><span title={account.email}>{account.email}</span><AccountTermSelect value={batchAccountTerms[account.key] || batchAccountTerm} onChange={(value) => setBatchAccountTerms((current) => ({ ...current, [account.key]: value }))} label={`${account.email} 的账号类型`} disabled={batchBusy} /></li>)}</ul>{startLoginOnAdd && <ProxyAssignments accounts={batchPreview} assignments={batchProxyAssignments} onChange={setBatchProxyAssignments} proxies={proxyState.proxies} defaultProxyId={selectedOperationProxyId} defaultOperationProxy={defaultOperationProxy} onManage={() => setProxyManagerOpen(true)} />}</>}
            {batchError && <div className="dialog-error" role="alert"><CircleAlert size={15} />{batchError}</div>}
            <div className="dialog-footer">
              <button type="button" className="cancel-button" onClick={() => setBatchOpen(false)} disabled={batchBusy}>取消</button>
              <button type="submit" className="primary-button" disabled={!batchText.trim() || batchBusy || countBatchLines(batchText) > 500 || Boolean(startLoginOnAdd && batchPreview && batchPreview.some((account) => !isProxySelectionResolved(batchProxyAssignments[account.key], proxyState.proxies, defaultOperationProxy)))}>
                {batchBusy ? <LoaderCircle className="spin" size={17} /> : <ListPlus size={17} />}
                {batchPreview ? startLoginOnAdd ? `创建 ${batchPreview.length} 条任务并上号` : `仅保存 ${batchPreview.length} 个账号` : startLoginOnAdd ? "下一步：选择代理" : "识别账号并预览"}
              </button>
            </div>
          </form>
        </div>
      )}
      {proxyChange && <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !proxyChangeBusy) setProxyChange(null); }}>
        <form className="batch-dialog proxy-action-dialog" role="dialog" aria-modal="true" aria-labelledby="change-proxy-title" onSubmit={saveAccountProxy} onKeyDown={(event) => { if (event.key === "Escape" && !proxyChangeBusy) setProxyChange(null); }}>
          <div className="dialog-header"><h2 id="change-proxy-title">更换账号代理</h2><button type="button" className="icon-button" aria-label="关闭更换代理" onClick={() => setProxyChange(null)} disabled={proxyChangeBusy}><X size={18} /></button></div>
          <p className="dialog-hint">{proxyChange.email}</p>
          <p className="dialog-hint">当前：{proxyChange.proxyEndpoint || "直连 / 尚未配置代理"}</p>
          <ProxySelect proxies={proxyState.proxies.filter((proxy) => !proxy.dynamicProfileId)} value={proxyChangeId} onChange={setProxyChangeId} label="新的账号代理" disabled={proxyChangeBusy} />
          <p className="dialog-hint">保存后供下次登录或账号安全操作使用，不会立即重新登录。CRS / Sub2API 的远端账号代理保持原配置。</p>
          <button type="button" className="selection-text-button" onClick={() => setProxyManagerOpen(true)} disabled={proxyChangeBusy}>管理代理列表</button>
          {proxyChangeError && <div className="dialog-error" role="alert">{proxyChangeError}</div>}
          <div className="dialog-footer"><button type="button" className="cancel-button" onClick={() => setProxyChange(null)} disabled={proxyChangeBusy}>取消</button><button type="submit" className="primary-button" disabled={proxyChangeBusy || !isProxySelectionResolved(proxyChangeId, proxyState.proxies.filter((proxy) => !proxy.dynamicProfileId))}>{proxyChangeBusy ? "正在保存…" : "保存代理"}</button></div>
        </form>
      </div>}

      {securityChooser && <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setSecurityChooser(null); }}>
        <section className="batch-dialog security-choice-dialog" role="dialog" aria-modal="true" aria-labelledby="security-choice-title">
          <div className="dialog-header"><div><h2 id="security-choice-title">{securityChooser.single ? "账号安全" : "批量账号安全"}</h2><span>{securityChooser.single ? securityChooser.jobs[0].email : `已选择 ${securityChooser.jobs.length} 个账号`}</span></div><button type="button" className="icon-button" aria-label="关闭账号安全操作" onClick={() => setSecurityChooser(null)}><X size={18} /></button></div>
          <p className="dialog-hint">选择操作后确认账号和 SOCKS5 代理。每项操作独立执行。</p>
          <div className="security-choice-list">{[
            { action: "rotate-totp", icon: <ShieldCheck size={21} />, description: "更新 2FA 密钥，并保存到账号详情。" },
            { action: "logout-all", icon: <LogOut size={21} />, description: "先重置当前 Work 工作环境，再登出所有设备并暂停自动重新登录。" },
            { action: "rotate-totp-logout-all", icon: <RefreshCw size={21} />, description: "更换并保存新密钥 → 重置 Work → 登出所有设备。" },
          ].map((choice) => {
            const count = securityChooser.jobs.filter((job) => job[securityPermission(choice.action)]).length;
            return <button type="button" className="security-choice" key={choice.action} disabled={!count || Boolean(batchAction)} onClick={() => prepareSecurityAction(choice.action, securityChooser.jobs, securityChooser.single)}><span className="security-choice-icon">{choice.icon}</span><span><strong>{securityActionLabel(choice.action)}</strong><small>{choice.description}</small></span><span className="security-choice-count">{securityChooser.single ? count ? "选择" : "暂不可用" : `${count} 个可操作`}</span></button>;
          })}</div>
          <div className="dialog-footer"><button type="button" className="cancel-button" onClick={() => setSecurityChooser(null)}>取消</button></div>
        </section>
      </div>}
      {proxyAction && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !batchAction) setProxyAction(null); }}>
          <form className="batch-dialog proxy-action-dialog" onSubmit={submitProxyAction} role="dialog" aria-modal="true" aria-labelledby="proxy-action-title">
            <div className="dialog-header"><div><h2 id="proxy-action-title">{proxyAction.title}</h2><span>{proxyAction.accounts.filter((account) => !account.skipped).length} 个账号</span></div><button type="button" className="icon-button" onClick={() => setProxyAction(null)} disabled={Boolean(batchAction)} title="关闭"><X size={18} /></button></div>
            {proxyAction.securityAction && <div className="security-action-notice">
              <p>{proxyAction.securityAction === "logout-all"
                ? "先重置所选账号的 ChatGPT Work 工作环境，确认重置成功后，再登出所有设备，包括本次操作使用的当前会话。登出提交后最多需要 30 分钟生效，并暂停自动重新登录；之后可手动重新登录。此操作不会更换 2FA。"
                : proxyAction.securityAction === "rotate-totp-logout-all"
                  ? "先重新验证账号并更换 2FA，确认新密钥已生效且保存到账号详情后，重置 ChatGPT Work，确认重置成功后再登出所有设备（含当前会话）。登出提交后最多需要 30 分钟生效，并暂停自动重新登录。后续步骤失败时会保留新密钥，并分别报告 Work 重置和登出结果。"
                  : "将重新验证账号，关闭原 2FA 后启用新的密钥。成功后新密钥保存到账号详情，后续登录会使用新密钥。此操作不会重置 Work、登出其他设备或暂停自动登录。"}</p>
              {proxyAction.securityAction !== "rotate-totp" && <p className="security-reset-scope"><strong>Work 重置范围：</strong>删除当前工作环境中的文件和其他本地数据，保留已保存到资料库的文件；下次工作时创建新环境。</p>}
              <p>全程仅使用 SOCKS5 代理。代理不可用时停止，不切换直连。</p>
            </div>}
            {!proxyActionResult && <fieldset className="security-proxy-fields" disabled={Boolean(batchAction)}>
              {proxyAction.securityAction && <label className="security-proxy-choice"><input type="checkbox" checked={securityUseStoredProxy} onChange={(event) => { setSecurityUseStoredProxy(event.target.checked); setProxyActionError(""); }} />沿用各账号已保存的 SOCKS5 代理</label>}
              {proxyAction.securityAction && securityUseStoredProxy ? <ul className="security-proxy-current">{proxyAction.accounts.map((account) => <li key={account.key}><strong>{account.email}</strong><span>{account.skipped ? "本次不符合条件，将跳过" : account.currentEndpoint || "未保存代理，请取消上方选项后分配 SOCKS5 代理"}</span></li>)}</ul>
                : <ProxyAssignments accounts={proxyAction.accounts} assignments={actionProxyAssignments} onChange={setActionProxyAssignments} proxies={proxyAction.securityAction ? securityProxies : proxyState.proxies} defaultProxyId={proxyAction.securityAction && !securityProxies.some((proxy) => proxy.id === selectedOperationProxyId) ? "" : selectedOperationProxyId} defaultOperationProxy={defaultOperationProxy} onManage={() => setProxyManagerOpen(true)} />}
              {proxyAction.securityAction && !securityUseStoredProxy && <p className="dialog-hint">{defaultOperationProxy?.configured ? "默认使用美国动态住宅 SOCKS5 代理，也可为各账号另选 SOCKS5 代理。" : "仅列出可确认协议的 SOCKS5 代理。请选择每个账号的代理；选择直连会被阻止。"}</p>}
            </fieldset>}
            {securityProxyError && <div className="dialog-error" role="alert"><CircleAlert size={15} />{securityProxyError}</div>}
            {proxyActionResult && <section className="security-batch-results" aria-label="提交结果" aria-live="polite">
              <p>已排队 {proxyActionResult.started} 个，跳过 {proxyActionResult.skipped} 个，失败 {proxyActionResult.errors.length} 个。排队不代表执行成功，请查看账号详情中的安全操作记录。</p>
              <ul>{proxyActionResult.results.map((result) => <li key={result.id}><strong>{result.email || shortId(result.id)}</strong><span>{({ started: "已排队", skipped: "已跳过", error: "提交失败" })[result.status] || result.status}{result.error ? `：${extractResponseMessage(result.error)}` : ""}</span></li>)}</ul>
            </section>}
            {proxyActionError && <div className="dialog-error" role="alert"><CircleAlert size={15} />{proxyActionError}</div>}
            <div className="dialog-footer"><button type="button" className="cancel-button" onClick={() => setProxyAction(null)} disabled={Boolean(batchAction)}>{proxyActionResult ? "关闭" : "取消"}</button>{!proxyActionResult && <button type="submit" className="primary-button" disabled={Boolean(batchAction) || (proxyAction.securityAction ? Boolean(securityProxyError) : proxyAction.accounts.some((account) => !account.skipped && !isProxySelectionResolved(actionProxyAssignments[account.key], proxyState.proxies, defaultOperationProxy)))}>{batchAction ? <LoaderCircle className="spin" size={16} /> : <LogIn size={16} />}确认并开始</button>}</div>
          </form>
        </div>
      )}
      {filterOpen && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => {
          if (event.target === event.currentTarget) setFilterOpen(false);
        }}>
          <form className="batch-dialog filter-dialog" onSubmit={applyEmailFilter} role="dialog" aria-modal="true" aria-labelledby="filter-title">
            <div className="dialog-header">
              <div>
                <h2 id="filter-title">筛选账号</h2>
                <span>{countBatchLines(filterText)} 个邮箱</span>
              </div>
              <button type="button" className="icon-button" onClick={() => setFilterOpen(false)} title="关闭">
                <X size={18} />
              </button>
            </div>
            <label className="batch-label" htmlFor="filter-input">每行输入一个完整邮箱地址</label>
            <textarea
              id="filter-input"
              value={filterText}
              onChange={(event) => setFilterText(event.target.value)}
              placeholder={"name1@icloud.com\nname2@icloud.com"}
              spellCheck="false"
              autoFocus
            />
            {filterError && <div className="dialog-error" role="alert"><CircleAlert size={15} />{filterError}</div>}
            <div className="dialog-footer">
              <button type="button" className="cancel-button" onClick={() => setFilterOpen(false)}>取消</button>
              <button type="submit" className="primary-button" disabled={!filterText.trim() || countBatchLines(filterText) > 500}>
                <Filter size={17} />应用筛选
              </button>
            </div>
          </form>
        </div>
      )}
      {proxyManagerOpen && <ProxyManager request={dynamicProxyRequest} proxies={proxyState.proxies} onClose={() => setProxyManagerOpen(false)} onSave={async (proxies) => {
        const selectedId = proxyState.selectedId === "direct" || proxies.some((proxy) => proxy.id === proxyState.selectedId)
          ? proxyState.selectedId : "";
        await saveSharedSetting("proxyLibrary", { proxies, selectedId });
        setProxyManagerOpen(false);
      }} />}
    </main>
  );
}

function requireSelectedProxyUrl(value) {
  if (typeof value !== "string" && !(value && (typeof value.dynamicProfileId === "string" || value.useDefaultProxy === true || value.useStoredProxy === true))) throw new Error("请先选择登录代理，或明确选择直连");
  return value;
}

function isProxySelectionResolved(id, proxies, defaultOperationProxy) {
  return operationProxySelection(id, defaultOperationProxy) === DEFAULT_OPERATION_PROXY_ID && Boolean(defaultOperationProxy?.configured) || id === "direct" || proxies.some((proxy) => proxy.id === id);
}

function isSocks5ProxyUrl(value) {
  if (typeof value !== "string" || !value.trim()) return false;
  try { const url = new URL(value); return ["socks5:", "socks5h:"].includes(url.protocol) && Boolean(url.hostname); }
  catch { return false; }
}

function securityPermission(action) {
  return ({ "rotate-totp": "canRotateTotp", "logout-all": "canLogoutAll", "rotate-totp-logout-all": "canRotateTotpLogoutAll" })[action];
}

function canUseAccountSecurity(job) {
  return Boolean(job.canRotateTotp || job.canLogoutAll || job.canRotateTotpLogoutAll);
}

function validateSecurityProxySelection(accounts, useStored, assignments, proxies, defaultOperationProxy) {
  const eligible = accounts.filter((account) => !account.skipped);
  if (!eligible.length) return "没有符合条件的账号。";
  for (const account of eligible) {
    if (useStored) {
      if (!isSocks5ProxyUrl(account.currentEndpoint)) return "有账号尚未保存 SOCKS5 代理，请取消沿用选项后逐个分配。";
    } else {
      const id = operationProxySelection(assignments[account.key], defaultOperationProxy);
      if (id === DEFAULT_OPERATION_PROXY_ID && defaultOperationProxy?.configured) continue;
      if (id === "direct") return "安全操作必须使用 SOCKS5 代理，不能选择直连。";
      const proxy = proxies.find((item) => item.id === id);
      if (!proxy || !isSocks5ProxyUrl(proxy.url)) return "请为每个待操作账号选择 SOCKS5 代理，空代理或其他协议不能提交。";
    }
  }
  return "";
}

function paginationItems(page, totalPages) {
  if (totalPages <= 7) return Array.from({ length: totalPages }, (_, index) => index + 1);
  const start = Math.max(2, Math.min(page - 1, totalPages - 4));
  const end = Math.min(totalPages - 1, Math.max(page + 1, 5));
  return [1, ...(start > 2 ? ["before"] : []), ...Array.from({ length: end - start + 1 }, (_, index) => start + index), ...(end < totalPages - 1 ? ["after"] : []), totalPages];
}

function compactJobPrompt(job) {
  if (job.loginDeferred && ["ready", "completed"].includes(job.status)) return "仅保存，待上号";
  if (job.status === "completed" && job.prompt === "授权完成，可以下载导入文件") return "授权完成，可下载";
  return job.prompt;
}

function EmptyState({ filtered = false, area = "active" }) {
  return (
    <tr>
      <td colSpan="8">
        <div className="empty-state">
          <div><Mail size={24} /></div>
          <h3>{filtered ? "没有匹配账号" : area === "resting" ? "暂无静置账号" : area === "retired" ? "暂无废号" : "暂无授权任务"}</h3>
          <p>{filtered ? "试试其他关键词，或清除搜索和筛选。" : area === "resting" ? "执行退出其他设备后，账号会显示在这里。" : area === "retired" ? "已确认无法使用的账号会显示在这里。" : "在右上方输入邮箱地址添加账号。"}</p>
        </div>
      </td>
    </tr>
  );
}

function JobRow({ job, crs, token, expanded, onToggleLogs, onError, selected, onToggleSelected, selectionSupported, smsProviderAvailable, smsProvider, onUpload, sub2apiUploadAvailable, totpSetupAvailable, passwordAddAvailable, forceReloginAvailable, accountProxyUrl, onSecurityAction, onChangeProxy, onUpdateAccountTerm }) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [value, setValue] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [termSaving, setTermSaving] = useState(false);

  async function moveAccount(area) {
    const label = area === "rest" ? "静置区" : "废号区";
    if (!window.confirm(`将 ${job.email} 移到${label}？移入后暂停自动登录和推送，资料会保留。`)) return;
    setSubmitting(true);
    try {
      await apiFetch(token, `/api/jobs/${job.id}/${area}`, { method: "POST", body: JSON.stringify(area === "retire" ? { reason: "手动移入废号区" } : {}) });
      onError("");
    } catch (failure) { onError(failure.message); }
    finally { setSubmitting(false); }
  }

  async function changeTerm(accountTerm) {
    setTermSaving(true);
    try {
      const data = await apiFetch(token, `/api/jobs/${job.id}/account-term`, { method: "POST", body: JSON.stringify({ accountTerm }) });
      onUpdateAccountTerm(data.job || { ...job, accountTerm });
      onError("");
    } catch (requestError) { onError(requestError.message); }
    finally { setTermSaving(false); }
  }

  useEffect(() => setValue(""), [job.status]);

  async function sendInput(action, submittedValue = value) {
    setSubmitting(true);
    try {
      await apiFetch(token, `/api/jobs/${job.id}/input`, {
        method: "POST",
        body: JSON.stringify({ action, value: submittedValue }),
      });
      setValue("");
      onError("");
    } catch (requestError) {
      onError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function cancel() {
    setSubmitting(true);
    try {
      await apiFetch(token, `/api/jobs/${job.id}/cancel`, { method: "POST" });
    } catch (requestError) {
      onError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function retry(loginFlow = "codex") {
    setSubmitting(true);
    try {
      await apiFetch(token, `/api/jobs/${job.id}/retry`, {
        method: "POST",
        body: JSON.stringify({ proxyUrl: requireSelectedProxyUrl(accountProxyUrl), loginFlow }),
      });
      onError("");
    } catch (requestError) {
      onError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function regenerate(loginFlow = "codex") {
    setSubmitting(true);
    try {
      await apiFetch(token, `/api/jobs/${job.id}/regenerate`, {
        method: "POST",
        body: JSON.stringify({ proxyUrl: requireSelectedProxyUrl(accountProxyUrl), loginFlow }),
      });
      onError("");
    } catch (requestError) {
      onError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function forceRelogin(loginFlow = "codex") {
    setSubmitting(true);
    try {
      await apiFetch(token, `/api/jobs/${job.id}/relogin`, {
        method: "POST",
        body: JSON.stringify({ proxyUrl: requireSelectedProxyUrl(accountProxyUrl), loginFlow }),
      });
      onError("");
    } catch (requestError) {
      onError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function setupTotp() {
    setSubmitting(true);
    try {
      await apiFetch(token, `/api/jobs/${job.id}/setup-2fa`, {
        method: "POST",
        body: JSON.stringify({ proxyUrl: requireSelectedProxyUrl(accountProxyUrl) }),
      });
      onError("");
    } catch (requestError) {
      onError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function addPassword() {
    if (!window.confirm("确定为该账号生成并添加随机强密码吗？成功后会自动更新账号原始信息。")) return;
    setSubmitting(true);
    try {
      await apiFetch(token, `/api/jobs/${job.id}/add-password`, {
        method: "POST",
        body: JSON.stringify({ proxyUrl: requireSelectedProxyUrl(accountProxyUrl) }),
      });
      onError("");
    } catch (requestError) {
      onError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function copyTotpSecret() {
    try {
      await navigator.clipboard.writeText(job.totpSetupSecret || "");
      onError("");
    } catch {
      onError("无法自动复制，请手动选择 2FA 密钥");
    }
  }

  async function requestSmsNumber() {
    if (!smsProvider.ready) return;
    setSubmitting(true);
    try {
      await apiFetch(token, `/api/jobs/${job.id}/sms-number`, {
        method: "POST",
        body: JSON.stringify({ providerId: smsProvider.id, config: smsProvider.config }),
      });
      onError("");
    } catch (requestError) {
      onError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function download() {
    try {
      const response = await fetch(`/api/jobs/${job.id}/download`, {
        headers: { "x-console-token": token },
      });
      if (!response.ok) throw new Error((await response.json()).error || "下载失败");
      await saveDownloadResponse(response, `${job.email}-sub2api-import-oauth-${localTimestamp()}.json`);
    } catch (requestError) {
      onError(requestError.message);
    }
  }

  const inputConfig = getInputConfig(job.status, job.currentPhone);
  const terminal = ["ready", "completed", "failed", "canceled", "reauth_required", "resume_available"].includes(job.status);

  return (
    <tr className={`job-row status-${job.status}`}>
      <td className="select-cell">
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggleSelected}
          disabled={!selectionSupported}
          aria-label={`选择 ${job.email}`}
        />
      </td>
      <td>
        <div className="account-cell">
          <div className="account-avatar">{job.email.slice(0, 1).toUpperCase()}</div>
          <div className="account-details"><strong title={job.email}>{job.email}</strong><div className="account-metadata"><span>{shortId(job.id)}</span><LoginMethodBadge job={job} /><AccountTermSelect value={job.accountTerm} onChange={changeTerm} label={`${job.email} 的账号类型`} disabled={termSaving} unknown className="row-account-term" /></div><span className="account-first-authorization" title={job.firstAuthorizedAtSource === "historical" ? "历史可追溯的最早授权记录，早于记录范围的授权可能未保留" : undefined}>{job.firstAuthorizedAtSource === "historical" ? "首次授权（可追溯）" : "首次授权"}：{job.firstAuthorizedAt ? <time dateTime={job.firstAuthorizedAt}>{formatDateTime(job.firstAuthorizedAt)}</time> : "未记录"}</span>{job.retired ? <RetiredStatus job={job} /> : job.resting && <RestingStatus job={job} />}{job.proxyEndpoint && <span className="account-proxy-endpoint" title={job.proxyEndpoint}><Globe2 size={11} />{job.proxyEndpoint}</span>}</div>
        </div>
      </td>
      <td><CrsAccountSettings crs={crs} job={job} /></td>
      <td><StatusBadge status={job.loginDeferred && ["ready", "completed"].includes(job.status) ? "saved_only" : job.status} /></td>
      <td className="step-cell">
        <div className="prompt-line" title={job.prompt}>{compactJobPrompt(job)}</div>
        {job.loginDeferred && <div className="saved-only-summary" title="仅保存模式：可先执行账号安全操作，不会自动上号或推送。">可执行账号安全操作</div>}
        {job.lastError && <div className="row-error">{extractResponseMessage(job.lastError)}</div>}
        {job.autoRepairBlocked && (
          <div className="row-error">号池自动登录已暂停：{extractResponseMessage(job.autoRepairBlockedReason || "请检查原因后手动重试")}</div>
        )}
        {job.totpSetupError && <div className="row-error">2FA：{extractResponseMessage(job.totpSetupError)}</div>}
        {job.passwordAddError && <div className="row-error">添加密码：{extractResponseMessage(job.passwordAddError)}</div>}
        {job.securityOperation && <div className={`security-operation-summary ${job.securityOperation.status === "needs_attention" || job.securityOperation.status === "failed" ? "row-error" : ""}`}>
          {securityActionLabel(job.securityOperation.action)}：{securityOperationSummary(job.securityOperation)}
          {job.securityOperation.error && <span>{extractResponseMessage(job.securityOperation.error)}</span>}
        </div>}
        {job.securityAutoLoginPaused && <div className="security-operation-summary">已暂停自动重新登录。需要恢复时，请手动重新登录。</div>}
        {job.mailApiError && job.status === "email_otp" && <div className="mail-error">{job.mailApiError}</div>}
        {job.currentPhone && ["working", "phone", "phone_otp"].includes(job.status) && (
          <div className="phone-target"><Smartphone size={13} />当前手机号：<strong>{job.currentPhone}</strong></div>
        )}
        {job.phoneError && <div className="phone-error"><CircleAlert size={13} />{job.phoneError}</div>}
        {job.smsStatus && !["idle", "unavailable"].includes(job.smsStatus) && (
          <div className={`sms-status ${job.smsStatus === "error" ? "error" : ""}`}>
            {job.smsStatus === "error" ? <CircleAlert size={13} /> : <PhoneIncoming size={13} />}
            <span>{smsStatusText(job)}</span>
          </div>
        )}
        {job.status === "totp_setup_otp" && job.totpSetupSecret && (
          <div className="totp-setup-secret">
            <span>2FA 密钥</span>
            <code>{job.totpSetupSecret}</code>
            <button type="button" className="icon-button" onClick={copyTotpSecret} title="复制 2FA 密钥">
              <Copy size={15} />
            </button>
          </div>
        )}
        {inputConfig && (
          <div className="inline-entry">
            <div className="compact-input">
              {inputConfig.icon}
              <input
                value={value}
                onChange={(event) => setValue(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && value && !submitting) sendInput(inputConfig.action);
                }}
                inputMode={inputConfig.inputMode}
                type={inputConfig.type || "text"}
                placeholder={inputConfig.placeholder}
                aria-label={inputConfig.placeholder}
                autoComplete={inputConfig.autoComplete || "one-time-code"}
              />
            </div>
            <button
              type="button"
              className="icon-button submit"
              onClick={() => sendInput(inputConfig.action)}
              disabled={!value || submitting}
              title={inputConfig.submitLabel}
            >
              {submitting ? <LoaderCircle className="spin" size={17} /> : <Send size={17} />}
            </button>
            {job.status === "email_otp" && (
              <button type="button" className="text-action" onClick={() => sendInput("resend_email", "")} disabled={submitting}>
                <RefreshCw size={14} />重发
              </button>
            )}
            {job.status === "phone_otp" && (
              <>
                <button type="button" className="text-action" onClick={() => sendInput("resend_phone", "")} disabled={submitting}>
                  <RefreshCw size={14} />重发
                </button>
                <button type="button" className="text-action" onClick={() => sendInput("change_phone", "")} disabled={submitting}>
                  <RotateCcw size={14} />换号
                </button>
              </>
            )}
            {job.status === "phone" && smsProviderAvailable && (
              <>
                <span className="input-separator" aria-hidden="true" />
                <button
                  type="button"
                  className="platform-number-button"
                  onClick={requestSmsNumber}
                  disabled={!smsProvider.ready || submitting || job.smsStatus === "requesting"}
                  title={smsProvider.ready ? `使用 ${smsProvider.name} 取号` : "请先完成接码平台配置"}
                >
                  {submitting || job.smsStatus === "requesting" ? <LoaderCircle className="spin" size={15} /> : <PhoneIncoming size={15} />}
                  {smsProvider.name || "平台"}取号
                </button>
              </>
            )}
          </div>
        )}
      </td>
      <td className="time-cell"><time dateTime={job.createdAt}>{formatDateTime(job.createdAt)}</time></td>
      <td className="operation-time-cell">
        <time dateTime={job.lastOperationAt || job.createdAt}>{formatDateTime(job.lastOperationAt || job.createdAt)}</time>
        <span>{operationLabel(job.lastOperationType)}</span>
      </td>
      <td>
        <div className="row-actions">
          <button type="button" className="secondary-button" onClick={() => setDetailsOpen(true)}>详情</button>
          {!job.resting && !job.retired && <button type="button" className="secondary-button" onClick={() => moveAccount("rest")} disabled={submitting}>移到静置区</button>}
          {!job.retired && <button type="button" className="secondary-button" onClick={() => moveAccount("retire")} disabled={submitting}>移到废号区</button>}
          <CopyCredentialsButton jobId={job.id} token={token} onError={onError} />
          <button type="button" className="secondary-button change-proxy-button" onClick={onChangeProxy} disabled={submitting || !job.canChangeProxy} title={job.proxyChangeBlockedReason || "更换账号下次操作使用的代理"}><Globe2 size={13} />更换代理</button>
          {detailsOpen && <AccountDetails jobId={job.id} token={token} refreshKey={`${job.securityOperation?.operationId || ""}:${job.securityOperation?.updatedAt || ""}:${job.accountTerm || ""}:${job.restingSince || ""}:${job.firstAuthorizedAt || ""}:${job.retiredAt || ""}:${job.retiredReason || ""}`} onClose={() => setDetailsOpen(false)} />}
          <button type="button" className="secondary-button account-security-button" onClick={onSecurityAction} disabled={submitting || !canUseAccountSecurity(job)}><ShieldCheck size={15} />账号安全<ChevronDown size={13} /></button>
          {job.canDownload && (
            <button type="button" className="download-button" onClick={download}>
              <Download size={16} />下载
            </button>
          )}
          {job.canDownload && !job.loginDeferred && sub2apiUploadAvailable && (
            <button type="button" className="secondary-button" onClick={onUpload} disabled={submitting} title="上传到已配置的 Sub2API 号池">
              <Send size={16} />上传
            </button>
          )}
          {job.canRegenerate && (
            <button type="button" className="regenerate-button" onClick={() => regenerate()} disabled={submitting} title="直接授权 Codex：优先使用刷新令牌，失效后自动重新登录">
              {submitting ? <LoaderCircle className="spin" size={16} /> : <RefreshCw size={16} />}
              直接授权 Codex
            </button>
          )}
          {job.canRegenerate && (
            <button type="button" className="regenerate-button" onClick={() => regenerate("legacy")} disabled={submitting} title="优先刷新授权；失效后先登录网页再完成 Codex 授权">
              <RefreshCw size={16} />登录账号后授权 Codex
            </button>
          )}
          {forceReloginAvailable && job.canForceRelogin && (
            <button type="button" className="relogin-button" onClick={() => forceRelogin()} disabled={submitting} title="跳过刷新令牌和旧检查点，完整重新登录后自动授权">
              {submitting ? <LoaderCircle className="spin" size={16} /> : <LogIn size={16} />}
              {job.loginDeferred ? "上号授权" : "重新登录"}
            </button>
          )}
          {forceReloginAvailable && job.canForceRelogin && (
            <button type="button" className="relogin-button" onClick={() => forceRelogin("legacy")} disabled={submitting} title="跳过刷新令牌和检查点，先登录网页再完成 Codex 授权">
              <LogIn size={16} />{job.loginDeferred ? "上号授权（旧）" : "重新登录（旧）"}
            </button>
          )}
          {totpSetupAvailable && job.canSetupTotp && (
            <button type="button" className="icon-button" onClick={setupTotp} disabled={submitting} title="设置 2FA">
              {submitting ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />}
            </button>
          )}
          {passwordAddAvailable && job.canAddPassword && (
            <button type="button" className="icon-button" onClick={addPassword} disabled={submitting} title="添加密码">
              {submitting ? <LoaderCircle className="spin" size={16} /> : <KeyRound size={16} />}
            </button>
          )}
          {job.canRetry && (
            <button type="button" className="retry-button" onClick={() => retry()} disabled={submitting}>
              {submitting ? <LoaderCircle className="spin" size={16} /> : <RefreshCw size={16} />}
              {job.securityCheckRequired ? "手动重试" : job.loginDeferred ? "直接授权 Codex" : job.canResume && job.loginFlow !== "legacy" ? "继续流程" : "直接授权 Codex"}
            </button>
          )}
          {job.canRetry && (
            <button type="button" className="retry-button" onClick={() => retry("legacy")} disabled={submitting} title="旧方式：先登录网页再授权；同一旧流程的检查点可继续使用">
              <RefreshCw size={16} />{job.loginDeferred ? "登录账号后授权 Codex" : job.canResume && job.loginFlow === "legacy" ? "继续流程（旧）" : "登录账号后授权 Codex"}
            </button>
          )}
          <button type="button" className="icon-button" onClick={onToggleLogs} title={expanded ? "收起日志" : "查看日志"}>
            <FileText size={17} />
            {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>
          {!terminal && (
            <button type="button" className="icon-button danger" onClick={cancel} disabled={submitting} title="取消任务">
              <Ban size={17} />
            </button>
          )}
        </div>
      </td>
    </tr>
  );
}

function JobLogs({ token, jobId }) {
  const [logs, setLogs] = useState("正在读取日志...");

  useEffect(() => {
    let stopped = false;
    const load = async () => {
      try {
        const data = await apiFetch(token, `/api/jobs/${jobId}/logs`);
        if (!stopped) setLogs(data.logs || "暂无日志");
      } catch (error) {
        if (!stopped) setLogs(`日志读取失败：${error.message}`);
      }
    };
    load();
    const timer = window.setInterval(load, 1_200);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [jobId, token]);

  return (
    <div className="log-panel">
      <div className="log-title"><FileText size={15} />协议日志</div>
      <pre>{logs}</pre>
    </div>
  );
}

function StatusBadge({ status }) {
  const config = {
    ready: ["等待执行", <Clock3 size={14} />],
    saved_only: ["仅保存", <FileText size={14} />],
    queued: ["排队中", <LoaderCircle size={14} />],
    starting: ["启动中", <LoaderCircle className="spin" size={14} />],
    working: ["处理中", <LoaderCircle className="spin" size={14} />],
    password: ["待密码", <KeyRound size={14} />],
    mfa_otp: ["待 2FA", <ShieldCheck size={14} />],
    totp_starting: ["准备 2FA", <LoaderCircle className="spin" size={14} />],
    password_add_starting: ["准备密码", <LoaderCircle className="spin" size={14} />],
    totp_setup_otp: ["激活 2FA", <ShieldCheck size={14} />],
    email_otp: ["待邮箱码", <Mail size={14} />],
    phone: ["待手机号", <Smartphone size={14} />],
    phone_otp: ["待手机码", <Smartphone size={14} />],
    finalizing: ["生成中", <LoaderCircle className="spin" size={14} />],
    refreshing: ["刷新授权", <RefreshCw className="spin" size={14} />],
    completed: ["已完成", <Check size={14} />],
    failed: ["失败", <CircleAlert size={14} />],
    canceled: ["已取消", <Ban size={14} />],
    reauth_required: ["待授权 Codex", <RefreshCw size={14} />],
    resume_available: ["可继续", <RotateCcw size={14} />],
  }[status] || [status, null];
  return <span className={`status-badge ${status}`}>{config[1]}{config[0]}</span>;
}

function LoginMethodBadge({ job }) {
  if (job.loginMode === "password") {
    const methods = ["密码", job.autoEmailOtp ? "自动收码" : "", job.hasTotpKey ? "2FA" : ""].filter(Boolean);
    return (
      <span className="mail-mode password-mode">
        {job.hasTotpKey ? <ShieldCheck size={12} /> : <KeyRound size={12} />}
        {methods.join(" + ")}
      </span>
    );
  }
  if (job.autoEmailOtp) {
    return (
      <span className={`mail-mode ${["error", "timeout"].includes(job.mailStatus) ? "error" : ""}`}>
        {job.hasTotpKey ? <ShieldCheck size={12} /> : <MailCheck size={12} />}
        {job.hasTotpKey ? "自动收码 + 2FA" : "自动收码"}
      </span>
    );
  }
  if (job.loginMode === "manual") {
    return (
      <span className="mail-mode unknown-mode">
        <CircleAlert size={12} />旧任务资料未记录
      </span>
    );
  }
  if (!job.hasTotpKey) return null;
  return (
    <span className="mail-mode">
      <ShieldCheck size={12} />邮箱码 + 2FA
    </span>
  );
}

function getInputConfig(status, currentPhone) {
  if (status === "password") {
    return { action: "password", placeholder: "输入账号密码", submitLabel: "提交密码", inputMode: "text", type: "password", autoComplete: "current-password", icon: <KeyRound size={15} /> };
  }
  if (status === "mfa_otp") {
    return { action: "mfa_otp", placeholder: "6 位 2FA 验证码", submitLabel: "提交 2FA 验证码", inputMode: "numeric", icon: <ShieldCheck size={15} /> };
  }
  if (status === "totp_setup_otp") {
    return { action: "totp_setup_otp", placeholder: "新 2FA 的 6 位验证码", submitLabel: "激活新的 2FA", inputMode: "numeric", icon: <ShieldCheck size={15} /> };
  }
  if (status === "email_otp") {
    return { action: "email_otp", placeholder: "6 位邮箱验证码", submitLabel: "提交邮箱验证码", inputMode: "numeric", icon: <Mail size={15} /> };
  }
  if (status === "phone") {
    return { action: "phone", placeholder: "+60123456789", submitLabel: "发送手机验证码", inputMode: "tel", icon: <Smartphone size={15} /> };
  }
  if (status === "phone_otp") {
    return { action: "phone_otp", placeholder: currentPhone ? `${currentPhone} 的验证码` : "手机验证码", submitLabel: "提交手机验证码", inputMode: "numeric", icon: <Smartphone size={15} /> };
  }
  return null;
}

function smsStatusText(job) {
  const providerName = job.smsProviderName || "接码平台";
  if (job.smsError) return `${providerName}：${job.smsError}`;
  return {
    requesting: `${providerName}：正在获取手机号`,
    number_acquired: `${providerName}：已获取手机号，正在发送验证码`,
    waiting_sms: `${providerName}：验证码已发送，正在等待短信`,
    submitting: `${providerName}：已收到验证码，正在自动提交`,
    submitted: `${providerName}：验证码已自动提交`,
    manual_submitted: `${providerName}：已停止自动读取，正在验证手动输入的验证码`,
    completed: `${providerName}：手机验证已通过，订单已完成`,
  }[job.smsStatus] || `${providerName}：处理中`;
}

async function saveDownloadResponse(response, fallbackName) {
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = downloadFilename(response.headers.get("content-disposition")) || fallbackName;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1_000);
}

function downloadFilename(contentDisposition) {
  if (!contentDisposition) return "";
  const encodedMatch = /filename\*\s*=\s*(?:UTF-8'')?([^;]+)/i.exec(contentDisposition);
  const plainMatch = /filename\s*=\s*(?:"([^"]+)"|([^;]+))/i.exec(contentDisposition);
  const rawName = encodedMatch?.[1] || plainMatch?.[1] || plainMatch?.[2] || "";
  try {
    return decodeURIComponent(rawName.trim().replace(/^"|"$/g, "")).replace(/[\\/]/g, "_");
  } catch {
    return rawName.trim().replace(/^"|"$/g, "").replace(/[\\/]/g, "_");
  }
}

function localTimestamp(date = new Date()) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

function formatMonitorResult(result) {
  if (!result || typeof result !== "object") return "号池巡检已完成";
  const parts = [`检查 ${Number(result.checked || 0)} 条异常记录`];
  if (result.started) parts.push(`已启动自动修复 ${result.started} 条`);
  if (result.updated) parts.push(`已更新 ${result.updated} 条`);
  if (result.blocked) parts.push(`已跳过 ${result.blocked} 条`);
  if (result.ineligible) parts.push(`需人工 ${result.ineligible} 条`);
  if (result.missingTask) parts.push(`本地无任务 ${result.missingTask} 条`);
  if (result.busy) parts.push(`正在运行 ${result.busy} 条`);
  if (result.cooldown) parts.push(`冷却中 ${result.cooldown} 条`);
  return parts.join("，");
}

function formatRelativeMonitorTime(value) {
  const elapsed = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(elapsed) || elapsed < 0) return "刚刚检查";
  if (elapsed < 60_000) return "刚刚检查";
  if (elapsed < 60 * 60_000) return `${Math.floor(elapsed / 60_000)} 分钟前检查`;
  return `${Math.floor(elapsed / (60 * 60_000))} 小时前检查`;
}

async function apiFetch(token, url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    ...options,
    headers: {
      "content-type": "application/json",
      "x-console-token": token,
      ...(options.headers || {}),
    },
  });
  return readResponse(response);
}

async function readResponse(response) {
  let data;
  try { data = await response.json(); } catch {
    throw new Error(`服务器返回了无法读取的响应：HTTP ${response.status}`);
  }
  if (!response.ok) {
    const failure = new Error(data.error || `请求失败：HTTP ${response.status}`);
    failure.status = response.status;
    failure.data = data;
    throw failure;
  }
  return data;
}

async function settingsFetch(token, url, options) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15_000);
  try {
    return await apiFetch(token, url, { ...options, signal: controller.signal });
  } catch (requestError) {
    if (requestError.name === "AbortError") throw new Error("保存配置超时，请重新连接以核对服务器上的配置后再试");
    throw requestError;
  } finally {
    window.clearTimeout(timeout);
  }
}

function shortId(id) {
  return `任务 ${id.slice(0, 8)}`;
}

function formatDateTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  const now = new Date();
  const isToday = date.getFullYear() === now.getFullYear()
    && date.getMonth() === now.getMonth()
    && date.getDate() === now.getDate();
  return new Intl.DateTimeFormat("zh-CN", {
    ...(isToday ? {} : { month: "2-digit", day: "2-digit" }),
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function operationLabel(type) {
  return ({
    account_saved: "仅保存账号",
    initial_authorization: "首次授权",
    reauthorize: "直接授权 Codex",
    relogin: "重新登录并授权",
    automatic_relogin: "号池自动重登并授权",
    resume: "继续中断流程",
    setup_2fa: "设置 2FA",
    "rotate-totp": "更换 2FA",
    rotate_totp: "更换 2FA",
    rotate_2fa: "更换 2FA",
    rotate_2fa_logout_all: "更换 2FA、重置 Work 并登出",
    "logout-all": "重置 Work 并登出",
    logout_all: "重置 Work 并登出",
    add_password: "添加密码",
    account_update: "更新账号资料",
    proxy_update: "更新代理 IP",
  })[type] || "账号操作";
}

function countBatchLines(value) {
  return String(value || "").split(/\r?\n/).filter((line) => line.trim()).length;
}

function parseEmailFilter(value) {
  const lines = String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim().toLowerCase())
    .filter(Boolean);
  if (!lines.length) throw new Error("请至少输入一个筛选邮箱");
  if (lines.length > 500) throw new Error("一次最多筛选 500 个邮箱");
  lines.forEach((email, index) => {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      throw new Error(`第 ${index + 1} 行邮箱格式错误`);
    }
  });
  return [...new Set(lines)];
}

function extractResponseMessage(value) {
  const text = String(value || "").trim();
  const jsonAt = text.indexOf("{");
  if (jsonAt >= 0) {
    try {
      const payload = JSON.parse(text.slice(jsonAt));
      const message = payload?.error?.message || payload?.message;
      if (typeof message === "string" && message.trim()) return message.trim();
    } catch {}
  }
  const match = text.match(/"message"\s*:\s*"((?:\\.|[^"\\])*)"/i);
  if (match) {
    try {
      return JSON.parse(`"${match[1]}"`).trim();
    } catch {
      return match[1].replace(/\\"/g, '"').replace(/\\n/g, "\n").trim();
    }
  }
  return text;
}

function readLocalSetting(key) {
  try {
    return window.localStorage.getItem(key) || "";
  } catch {
    return "";
  }
}

function readSmsProviderSettings() {
  try {
    const stored = JSON.parse(window.localStorage.getItem(SMS_PROVIDER_SETTINGS_KEY) || "null");
    if (stored && typeof stored === "object" && stored.configs && typeof stored.configs === "object") {
      return normalizeSmsProviderSettings(stored);
    }
  } catch {}
  return {
    selectedProviderId: "luban",
    configs: {
      luban: {
        apiKey: readLocalSetting(LUBAN_API_KEY_STORAGE_KEY),
        serviceId: readLocalSetting(LUBAN_SERVICE_ID_STORAGE_KEY),
      },
    },
  };
}

function defaultSmsProviderSettings() {
  return { selectedProviderId: "luban", configs: { luban: { apiKey: "", serviceId: "" } } };
}

function normalizeSmsProviderSettings(value) {
  return value && typeof value === "object" && value.configs && typeof value.configs === "object"
    ? { selectedProviderId: String(value.selectedProviderId || "luban"), configs: value.configs }
    : defaultSmsProviderSettings();
}

function readLegacySharedSettings() {
  const settings = {};
  const warnings = [];
  const keys = {
    proxyLibrary: [PROXY_LIBRARY_STORAGE_KEY, LEGACY_PROXY_STORAGE_KEY],
    sms: [SMS_PROVIDER_SETTINGS_KEY, LUBAN_API_KEY_STORAGE_KEY, LUBAN_SERVICE_ID_STORAGE_KEY],
    mail: [MAIL_REQUEST_SETTINGS_KEY],
    sub2api: [SUB2API_UPLOAD_SETTINGS_KEY],
  };
  const legacyProxyLibrary = readProxyState();
  const proxyLibrary = {
    ...legacyProxyLibrary,
    selectedId: legacyProxyLibrary.selectedId === "direct" || legacyProxyLibrary.proxies.some((proxy) => proxy.id === legacyProxyLibrary.selectedId)
      ? legacyProxyLibrary.selectedId : "",
  };
  if (proxyLibrary.proxies.length || proxyLibrary.selectedId === "direct") settings.proxyLibrary = proxyLibrary;
  const sms = readSmsProviderSettings();
  if (Object.values(sms.configs || {}).some((config) => config && typeof config === "object"
    && Object.values(config).some((value) => String(value ?? "").trim()))) settings.sms = sms;
  const mail = readMailRequestSettings();
  if (mail.url || mail.method === "POST" || !["", "{}"].includes(mail.headersText.replace(/\s/g, ""))) {
    try { buildMailRequestConfig(mail); settings.mail = mail; } catch {
      warnings.push("旧浏览器的邮件 API 配置格式有误，已跳过导入；请打开邮件 API 配置重新保存。原浏览器数据已保留。");
    }
  }
  const sub2api = readSub2ApiSettings();
  if (sub2api.baseUrl || sub2api.adminApiKey || sub2api.groupIds.length) settings.sub2api = sub2api;
  return { settings, keys, warnings };
}

function removeMigratedLocalSettings(legacy, shared, keys) {
  const normalizers = { proxyLibrary: normalizeProxyState, sms: normalizeSmsProviderSettings, mail: normalizeMailRequestSettings, sub2api: normalizeSub2ApiSettings };
  for (const [section, value] of Object.entries(legacy)) {
    if (!Object.hasOwn(shared, section)) continue;
    if (JSON.stringify(normalizers[section](value)) !== JSON.stringify(normalizers[section](shared[section]))) continue;
    try { keys[section].forEach((key) => window.localStorage.removeItem(key)); } catch {}
  }
}

function normalizeMailRequestSettings(value) {
  const stored = value && typeof value === "object" ? value : {};
  let headersText = typeof stored.headersText === "string" ? stored.headersText : "";
  if (!headersText && stored.headers && typeof stored.headers === "object" && !Array.isArray(stored.headers)) {
    headersText = JSON.stringify(stored.headers, null, 2);
  }
  return {
    method: String(stored.method || "GET").toUpperCase() === "POST" ? "POST" : "GET",
    url: typeof stored.url === "string" ? stored.url.trim() : "",
    headersText: headersText.trim() || "{}",
  };
}

function readMailRequestSettings(value) {
  try {
    const stored = value || JSON.parse(window.localStorage.getItem(MAIL_REQUEST_SETTINGS_KEY) || "null");
    return normalizeMailRequestSettings(stored);
  } catch {
    return normalizeMailRequestSettings({});
  }
}

function buildMailRequestConfig(settings) {
  const normalized = normalizeMailRequestSettings(settings);
  let headers;
  try {
    headers = JSON.parse(normalized.headersText || "{}");
  } catch {
    throw new Error("请求头必须是有效的 JSON 对象");
  }
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
    throw new Error("请求头必须是 JSON 对象，例如 {\"Authorization\":\"Bearer ...\"}");
  }
  if (normalized.method === "POST") {
    try {
      const parsedUrl = new URL(normalized.url);
      if (!["http:", "https:"].includes(parsedUrl.protocol)) throw new Error();
    } catch {
      throw new Error("POST 模式必须填写有效的 HTTP 或 HTTPS 请求 URL");
    }
  }
  return {
    method: normalized.method,
    url: normalized.method === "POST" ? normalized.url : "",
    headers,
  };
}

function formatMailRequestSummary(settings) {
  try {
    const config = buildMailRequestConfig(settings);
    const headerCount = Object.keys(config.headers).length;
    return `${config.method === "POST" ? "已配置统一 URL · " : ""}${headerCount} 个请求头`;
  } catch {
    return "配置需要检查";
  }
}

function normalizeSub2ApiSettings(value) {
  const stored = value && typeof value === "object" ? value : {};
  const rawGroupIds = Array.isArray(stored.groupIds)
    ? stored.groupIds
    : String(stored.groupId || "").trim()
      ? [stored.groupId]
      : [];
  return {
    baseUrl: String(stored.baseUrl || ""),
    adminApiKey: String(stored.adminApiKey || ""),
    groupIds: [...new Set(rawGroupIds.map((id) => String(id).trim()).filter(Boolean))],
    proxyId: String(stored.proxyId || ""),
    concurrency: String(stored.concurrency ?? ""),
    loadFactor: String(stored.loadFactor ?? ""),
    priority: String(stored.priority ?? ""),
    modelWhitelist: String(stored.modelWhitelist || ""),
    codexFingerprintMode: ["off", "device", "session", "full"].includes(stored.codexFingerprintMode)
      ? stored.codexFingerprintMode
      : "session",
    monitorEnabled: stored.monitorEnabled === true,
  };
}

function readSub2ApiSettings(value) {
  try {
    const stored = value || JSON.parse(window.localStorage.getItem(SUB2API_UPLOAD_SETTINGS_KEY) || "null");
    if (stored && typeof stored === "object") return normalizeSub2ApiSettings(stored);
  } catch {}
  return normalizeSub2ApiSettings({});
}

function formatSub2ApiProxy(proxy) {
  const protocol = String(proxy.protocol || "http").replace(/:\/\/$/, "");
  const host = String(proxy.host || "");
  const port = proxy.port ? `:${proxy.port}` : "";
  const endpoint = host ? `${protocol}://${host}${port}` : "地址未知";
  const ip = String(proxy.ipAddress || "").trim();
  return `${proxy.name || `代理 ${proxy.id}`} | ${endpoint}${ip ? ` | 出口 IP：${ip}` : ""}`;
}

function withSmsProviderDefaults(definitions, settings) {
  const configs = { ...(settings?.configs || {}) };
  definitions.forEach((provider) => {
    const current = { ...(configs[provider.id] || {}) };
    provider.fields.forEach((field) => {
      if (!String(current[field.key] || "").trim() && field.defaultValue) current[field.key] = field.defaultValue;
    });
    configs[provider.id] = current;
  });
  const selectedProviderId = definitions.some((provider) => provider.id === settings?.selectedProviderId)
    ? settings.selectedProviderId
    : definitions[0]?.id || settings?.selectedProviderId || "luban";
  return { selectedProviderId, configs };
}

function resolveSmsProvider(definitions, settings) {
  const normalized = withSmsProviderDefaults(definitions, settings || {});
  const definition = definitions.find((provider) => provider.id === normalized.selectedProviderId) || null;
  const config = definition ? normalized.configs[definition.id] || {} : {};
  const requiredFieldsReady = Boolean(definition) && definition.fields.every((field) => (
    field.required === false || String(config[field.key] || "").trim()
  ));
  const customEntries = definition?.id === "custom" ? inspectCustomSmsEntries(config.entries) : null;
  const ready = requiredFieldsReady && !customEntries?.error;
  const summary = definition?.id === "custom"
    ? (customEntries?.count ? `${customEntries.count} 个号码` : "")
    : definition
    ? definition.fields
      .filter((field) => field.summary || field.summaryKey)
      .map((field) => config[field.summaryKey || field.key])
      .filter(Boolean)
      .join(" / ")
    : "";
  return {
    id: definition?.id || "",
    name: definition?.name || "",
    definition,
    config,
    ready,
    summary,
  };
}

function inspectCustomSmsEntries(value) {
  const lines = String(value || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length) return { count: 0, error: "请粘贴至少一条手机号和接码 API" };
  if (lines.length > 500) return { count: 0, error: "自定义接码一次最多导入 500 条" };
  const phones = new Set();
  for (let index = 0; index < lines.length; index += 1) {
    const delimiterAt = lines[index].indexOf("----");
    if (delimiterAt < 0) return { count: 0, error: `第 ${index + 1} 行格式错误，请使用 手机号----接码API` };
    const phone = lines[index].slice(0, delimiterAt).trim();
    const apiUrl = lines[index].slice(delimiterAt + 4).trim();
    if (!/^\+[1-9]\d{6,14}$/.test(phone)) {
      return { count: 0, error: `第 ${index + 1} 行手机号必须使用 +861871291167 这种国际格式` };
    }
    try {
      const parsed = new URL(apiUrl);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("invalid protocol");
    } catch {
      return { count: 0, error: `第 ${index + 1} 行接码 API 必须是有效的 HTTP 或 HTTPS 地址` };
    }
    phones.add(phone);
  }
  return { count: phones.size, error: "" };
}

function formatSmsCountryName(option) {
  if (option.iso && REGION_NAMES) {
    try {
      return REGION_NAMES.of(option.iso) || option.title;
    } catch {}
  }
  return option.title || `国家 ${option.country}`;
}

function formatSmsPriceOption(option) {
  const name = formatSmsCountryName(option);
  return `${name} | 价格 ${option.price} | 库存 ${option.count}`;
}

function mergeJobs(...groups) {
  const unique = new Map();
  groups.flat().forEach((job) => {
    if (!unique.has(job.id)) unique.set(job.id, job);
  });
  return [...unique.values()];
}

const appRoot = globalThis.__chatgptOnboardingRoot || createRoot(document.getElementById("root"));
globalThis.__chatgptOnboardingRoot = appRoot;
appRoot.render(<App />);
