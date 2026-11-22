let latestSnap = null;
let ws = null;
let knownDevices = new Set();
let currentLang = localStorage.getItem("aegis_lang") || "";

const I18N = {
  en: {
    mode_system: "System",
    mode_router: "Router + AI",
    mode_demo: "Demo",
    tip_mode_system: "Tier 1: Personal OS Kernel Socket & Process Shield (no router needed)",
    tip_mode_router: "Tier 2: Connect Router via SSH or get AI Setup Prompt",
    tip_mode_demo: "Run synthetic L7 DPI + JA3 + Ghost-Socket simulation",
    btn_pause: "⏸ Pause",
    btn_resume: "▶ Resume",
    btn_idle_off: "Silence Mode: OFF",
    btn_idle_on: "🚨 SILENCE MODE: ARMED",
    btn_import_pcap: ".PCAP",
    btn_export_pcap: "PCAP",
    btn_report: "Report",
    btn_update_feeds: "Feeds",
    btn_updating_feeds: "⏳...",
    btn_clear: "Reset",
    btn_close: "Close",
    btn_refresh_feeds_now: "Download Fresh Feeds Now",
    pcap_import_tip: "Load an offline .pcap file for L7 DPI & Threat Intel analysis",
    pcap_export_tip: "Download rolling packet ring buffer as Wireshark .pcap",
    report_export_tip: "Download Forensic Security Report (.md)",
    strip_title: "🛡 Tier 1 Personal System Shield is active on this OS.",
    strip_desc: "Want whole-home Wi-Fi/IoT visibility, wire-speed TLS JA3 DPI, and Out-of-Band Rootkit detection?",
    btn_unlock_tier2: "Connect Router / Get AI Setup Prompt",
    status_router: "LIVE: ROUTER STREAM",
    status_system: "LIVE: OS SYSTEM SHIELD",
    status_demo: "DEMO SIMULATION",
    status_pcap: "OFFLINE PCAP",
    status_paused: "PAUSED (0% LOAD)",
    status_error: "STREAM ERROR",
    kpi_shield: "Shield Posture",
    kpi_throughput: "Live Throughput",
    kpi_sessions: "Active Flows / Packets",
    kpi_rootkit: "Kernel & Anti-Rootkit",
    kpi_alerts: "Security Events (IDS / IOC)",
    chart_title: "REAL-TIME THROUGHPUT (90s, MBPS)",
    tab_flows: "Live Connections (NGFW)",
    tab_rootkit: "Processes, Signatures & Anti-Rootkit",
    tab_dpi: "Apps, Network Hosts & DNS",
    tab_alerts: "Threat & Anomaly Log (IDS)",
    tab_shield: "Network Control & Router Audit",
    tab_intel: "Threat Intel Feeds",
    search_placeholder: "Search domain, SNI, IP, JA3, process, SHA-256, BGP ASN...",
    opt_all_devices: "All Hosts / Devices",
    opt_all_routes: "All Routes (WAN + VPN)",
    opt_route_wan: "WAN Direct Only",
    opt_route_vpn: "VPN Tunnel Only",
    opt_route_lan: "Internal LAN",
    opt_risk_all: "All Risk Levels",
    opt_risk_alerts: "Alerts & Anomalies Only",
    opt_risk_nodns: "No Domain / Direct-to-IP",
    opt_risk_ghost: "Hidden Ghost Sockets Only",
    chk_freeze: "Freeze Table",
    th_risk: "Risk",
    th_device: "Host / Device",
    th_process: "OS Process / Signature",
    th_app: "Application",
    th_domain: "Domain / TLS SNI",
    th_dest: "Destination (IP:Port • Country / ASN)",
    th_route: "Route",
    th_volume: "Traffic (↓ / ↑)",
    th_rate: "Rate",
    th_proc_exe: "Process",
    th_proc_sig: "Code Signature",
    th_proc_path: "Executable Path",
    th_flows_cnt: "Flows",
    th_sample_targets: "Sample Remote Targets",
    th_alerts_cnt: "Alerts",
    th_time: "Time",
    th_qname: "Domain (QNAME)",
    th_resolved: "Resolved IPs (A / AAAA)",
    th_severity: "Severity",
    th_sig_mitre: "Rule / MITRE",
    th_host_proc: "Host / Process",
    th_target: "Target",
    th_event_desc: "Security Event & Forensic Details",
    th_status: "Status",
    th_feed_name: "Feed / Provider",
    th_ioc_cnt: "Loaded Indicators",
    th_updated: "Last Updated",
    th_capability: "Capability",
    panel_procs_title: "Active Host Executables Communicating on the Network",
    panel_top_apps: "Top Identified Applications & Services",
    panel_lan_devices: "Discovered Hosts & LAN Inventory (Click to Filter)",
    panel_passive_dns: "DNS Resolution Stream (Gateway Passive DNS / OS Resolver Cache)",
    panel_alerts_title: "NGFW IDS Signature & Behavioral Anomaly Log",
    panel_blocks_title: "Active Network Containment Rules (Router Firewall)",
    panel_audit_title: "Router Perimeter Security Audit (Read-Only)",
    panel_tiers_title: "Two-Tier Digital Shield Architecture: System Level vs. Router Network Level",
    panel_feeds_title: "Active Threat Intelligence Feeds & Signature Packs",
    btn_flush_rules: "Unblock All",
    btn_block_wan_ip: "Block External IP on Router",
    btn_run_audit: "Run Router Audit",
    btn_open_ai_wizard: "Router & AI Setup Wizard",
    drawer_title: "Forensic Flow Inspection & Active Response",
    modal_router_title: "Tier 2 Router Shield & AI Setup Assistant",
    mtab_connect: "1. Connect Router via SSH",
    mtab_ai: "2. AI Prompt to Configure My Router",
    modal_connect_desc: "Aegis streams packet headers over SSH using lightweight tcpdump (0% router CPU/RAM when paused or closed). Public-key authentication only — never stores router passwords.",
    modal_ai_desc: "Enter your router model below and copy the generated prompt into ChatGPT, Claude, Gemini, or DeepSeek. The AI will give you exact, safe commands to set up SSH keys and tcpdump for Aegis.",
    lbl_router_model: "Your Router Model / Firmware",
    lbl_router_ip: "Router LAN IP",
    btn_test_ssh: "Test SSH & tcpdump",
    btn_activate_tier2: "Connect & Enable Tier 2",
    btn_copy_prompt: "Copy AI Prompt",
    no_flows: "No active flows match the current filter",
    waiting_procs: "Waiting for active network sockets...",
    waiting_dns: "Waiting for DNS resolutions...",
    no_alerts: "✓ Zero suspicious IDS detections or hidden Ghost Sockets observed",
    no_rules: "No active router block or quarantine rules",
    audit_hint: "Connect a router (Tier 2) and click 'Run Router Audit' to check WAN firewall DROP policy, SSH key-only auth, DNS rebind protection, and UPnP exposure.",
    external_dev: "External LAN Host",
    short_socket: "Ephemeral Socket",
    this_host: "This Host",
    direct_ip_tag: "[Direct IP]",
    preexisting_tag: "[Established Socket]",
    rootkit_explain_t1: "<strong>Tier 1 — Personal System Shield:</strong> Inspects live OS kernel TCP/UDP socket tables every 250 ms, verifies binary digital signatures (<code>Authenticode</code> / <code>codesign</code>) + <code>SHA-256</code> hashes, correlates the OS DNS Resolver Cache, and matches 50,000+ Threat Intel IOCs. <em>Connect a router (Tier 2) to add Out-of-Band wire verification against kernel rootkits (GHOST SOCKET).</em>",
    rootkit_explain_t2: "<strong>Tier 2 — Out-of-Band Anti-Rootkit Shield:</strong> Packets are captured <em>outside</em> this computer on the physical router bridge and cross-checked every 250 ms against the local OS kernel socket table. Even if a kernel rootkit hides its PID and sockets from the OS, it cannot hide frames crossing the physical gateway — immediately triggering a <strong>GHOST SOCKET</strong> alert.",
    intel_explain: "All Threat Intelligence indicators (botnet C2 IPs, malicious TLS <code>JA3</code> fingerprints, Tor exit nodes, and URLhaus malware domains) are stored and evaluated <strong>locally on your workstation</strong> inside <code>data/feeds/</code>, consuming <strong>0 bytes of RAM/flash</strong> on your router.",
  },
  ru: {
    mode_system: "Система",
    mode_router: "Роутер + ИИ",
    mode_demo: "Демо",
    tip_mode_system: "Уровень 1: Персональный щит на уровне ОС (сокеты, процессы, подписи, без роутера)",
    tip_mode_router: "Уровень 2: Подключить роутер по SSH или получить ИИ-промпт настройки",
    tip_mode_demo: "Запустить демо-симуляцию L7 DPI + JA3 + перехвата руткита Ghost Socket",
    btn_pause: "⏸ Пауза",
    btn_resume: "▶ Старт",
    btn_idle_off: "Режим тишины: ВЫКЛ",
    btn_idle_on: "🚨 РЕЖИМ ТИШИНЫ: ВКЛ",
    btn_import_pcap: ".PCAP",
    btn_export_pcap: "PCAP",
    btn_report: "Отчёт",
    btn_update_feeds: "Базы",
    btn_updating_feeds: "⏳...",
    btn_clear: "Сброс",
    btn_close: "Закрыть",
    btn_refresh_feeds_now: "Скачать свежие базы угроз сейчас",
    pcap_import_tip: "Загрузить готовый .pcap файл для L7 DPI и проверки по базам угроз",
    pcap_export_tip: "Скачать кольцевой буфер пакетов в формате Wireshark (.pcap)",
    report_export_tip: "Скачать форензик-отчёт ИБ в формате Markdown (.md)",
    strip_title: "🛡 Активен Уровень 1 — Персональный системный щит (на уровне ОС).",
    strip_desc: "Хотите контроль всей домашней сети (Wi-Fi/IoT), L7 DPI с TLS JA3 и внешний перехват руткитов?",
    btn_unlock_tier2: "Подключить роутер / Получить ИИ-промпт настройки",
    status_router: "LIVE: СЪЁМ С РОУТЕРА",
    status_system: "LIVE: СИСТЕМНЫЙ ЩИТ ОС",
    status_demo: "DEMO: СИМУЛЯЦИЯ",
    status_pcap: "OFFLINE: PCAP",
    status_paused: "ПАУЗА (0% НАГРУЗКИ)",
    status_error: "ОШИБКА ПОТОКА",
    kpi_shield: "Индекс защиты",
    kpi_throughput: "Живой трафик",
    kpi_sessions: "Потоки / Пакеты",
    kpi_rootkit: "Ядро ОС и Анти-Руткит",
    kpi_alerts: "События ИБ (IDS / IOC)",
    chart_title: "РЕАЛЬНОЕ ВРЕМЯ (90 СЕК, МБИТ/С)",
    tab_flows: "Живые соединения (NGFW)",
    tab_rootkit: "Процессы, Подписи и Анти-Руткит",
    tab_dpi: "Приложения, Устройства и DNS",
    tab_alerts: "Журнал угроз и Аномалий (IDS)",
    tab_shield: "Контроль сети и Аудит роутера",
    tab_intel: "Базы сигнатур (Threat Intel)",
    search_placeholder: "Поиск: домен, SNI, IP, JA3, процесс, SHA-256, провайдер ASN...",
    opt_all_devices: "Все узлы и устройства",
    opt_all_routes: "Все маршруты (WAN + VPN)",
    opt_route_wan: "Только прямой WAN",
    opt_route_vpn: "Только через VPN",
    opt_route_lan: "Локальная сеть (LAN)",
    opt_risk_all: "Все уровни риска",
    opt_risk_alerts: "Только аномалии и алерты",
    opt_risk_nodns: "Без домена / Прямой IP",
    opt_risk_ghost: "Только скрытые (Ghost Sockets)",
    chk_freeze: "Заморозить таблицу",
    th_risk: "Риск",
    th_device: "Узел / Устройство",
    th_process: "Процесс ОС / Подпись",
    th_app: "Приложение",
    th_domain: "Домен / TLS SNI",
    th_dest: "Назначение (IP:Порт • Страна / ASN)",
    th_route: "Маршрут",
    th_volume: "Объём (↓ / ↑)",
    th_rate: "Скорость",
    th_proc_exe: "Процесс",
    th_proc_sig: "Цифровая подпись",
    th_proc_path: "Путь исполняемого файла",
    th_flows_cnt: "Потоков",
    th_sample_targets: "Примеры узлов назначения",
    th_alerts_cnt: "Алерты",
    th_time: "Время",
    th_qname: "Домен (QNAME)",
    th_resolved: "IP-адреса (A / AAAA)",
    th_severity: "Уровень",
    th_sig_mitre: "Правило / MITRE",
    th_host_proc: "Узел / Процесс",
    th_target: "Цель",
    th_event_desc: "Событие и детальное описание",
    th_status: "Статус",
    th_feed_name: "База сигнатур / Поставщик",
    th_ioc_cnt: "Загружено индикаторов",
    th_updated: "Обновлено",
    th_capability: "Возможность",
    panel_procs_title: "Активные программы этого компьютера в сети",
    panel_top_apps: "Топ распознанных приложений и сервисов",
    panel_lan_devices: "Обнаруженные устройства сети (клик — фильтр)",
    panel_passive_dns: "Поток DNS-записей (Passive DNS шлюза / Кэш ОС)",
    panel_alerts_title: "Журнал срабатываний сигнатур и поведенческих аномалий (IDS)",
    panel_blocks_title: "Активные блокировки и карантин на роутере",
    panel_audit_title: "Аудит безопасности периметра роутера (Read-Only)",
    panel_tiers_title: "Двухуровневая архитектура Aegis: Уровень системы ↔ Уровень всей сети",
    panel_feeds_title: "Подключённые базы индикаторов угроз (Threat Intelligence)",
    btn_flush_rules: "Снять все блокировки",
    btn_block_wan_ip: "Заблокировать внешний IP на роутере",
    btn_run_audit: "Проверить роутер",
    btn_open_ai_wizard: "Мастер роутера + ИИ-промпт",
    drawer_title: "Детальная форензика соединения и Активная защита",
    modal_router_title: "Уровень 2: Сетевой щит роутера и ИИ-помощник настройки",
    mtab_connect: "1. Подключить роутер по SSH",
    mtab_ai: "2. ИИ-промпт для настройки вашего роутера",
    modal_connect_desc: "Aegis читает заголовки пакетов по SSH через лёгкий tcpdump (0% нагрузки на CPU/RAM роутера в паузе). Используется вход только по SSH-ключу — пароли роутера нигде не хранятся.",
    modal_ai_desc: "Укажите модель вашего роутера и скопируйте готовый промпт в ChatGPT, Claude, Gemini или DeepSeek. ИИ выдаст точные безопасные команды под вашу прошивку для настройки SSH-ключа и tcpdump.",
    lbl_router_model: "Модель вашего роутера / Прошивка",
    lbl_router_ip: "LAN IP роутера",
    btn_test_ssh: "Проверить SSH и tcpdump",
    btn_activate_tier2: "Подключить Уровень 2",
    btn_copy_prompt: "Скопировать ИИ-промпт",
    no_flows: "Нет активных соединений по выбранному фильтру",
    waiting_procs: "Ожидание активных сетевых соединений...",
    waiting_dns: "Ожидание DNS-записей...",
    no_alerts: "✓ Подозрительных срабатываний сигнатур и скрытых руткит-соединений не обнаружено",
    no_rules: "Активных правил блокировки или карантина на роутере нет",
    audit_hint: "Подключите роутер (Уровень 2) и нажмите «Проверить роутер» для read-only проверки фаервола WAN, защиты SSH, DNS Rebind и открытых портов UPnP.",
    external_dev: "Устройство в LAN",
    short_socket: "Краткосрочн. сокет",
    this_host: "Этот ПК",
    direct_ip_tag: "[Прямой IP]",
    preexisting_tag: "[Активный сокет]",
    rootkit_explain_t1: "<strong>Уровень 1 — Персональный системный щит (на уровне ОС):</strong> Каждые 250 мс опрашивает ядерную таблицу TCP/UDP сокетов ОС, проверяет цифровые подписи программ (<code>Authenticode</code> / <code>codesign</code>) и хэши <code>SHA-256</code>, читает DNS-кэш системы и сверяет соединения с 50 000+ индикаторами угроз. <em>Подключите роутер (Уровень 2), чтобы добавить внешнюю сверку пакетов против ядерных руткитов (GHOST SOCKET).</em>",
    rootkit_explain_t2: "<strong>Уровень 2 — Внешний Анти-Руткит и Сетевой щит:</strong> Трафик перехватывается <em>снаружи</em> компьютера прямо на мосту роутера и каждые 250 мс сверяется с ядерной таблицей сокетов ОС. Даже если ядерный руткит скроет свой PID и сокет от самой ОС, роутер увидит его пакеты на проводе и мгновенно поднимет тревогу <strong>GHOST SOCKET</strong>.",
    intel_explain: "Все базы индикаторов компрометации (IOC: IP ботнетов, вредоносные <code>JA3</code>, узлы Tor и домены URLhaus) хранятся и проверяются <strong>локально на вашем компьютере</strong> в папке <code>data/feeds/</code>, занимая <strong>0 байт памяти на роутере</strong>.",
  },
};

function t(key) {
  const dict = I18N[currentLang] || I18N.en;
  return dict[key] || I18N.en[key] || key;
}

function applyStaticTranslations() {
  document.documentElement.lang = currentLang;
  document.getElementById("btnLang").innerText = currentLang.toUpperCase();
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const k = el.getAttribute("data-i18n");
    if (k) el.innerText = t(k);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const k = el.getAttribute("data-i18n-placeholder");
    if (k) el.setAttribute("placeholder", t(k));
  });
  document.querySelectorAll("[data-i18n-title]").forEach((el) => {
    const k = el.getAttribute("data-i18n-title");
    if (k) el.setAttribute("title", t(k));
  });
  const tiBox = document.getElementById("intelExplainBox");
  if (tiBox) tiBox.innerHTML = t("intel_explain");
  refreshAiPrompt();
}

function toggleLanguage() {
  currentLang = currentLang === "ru" ? "en" : "ru";
  localStorage.setItem("aegis_lang", currentLang);
  applyStaticTranslations();
  renderAll();
}

function esc(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtBytes(b) {
  const units = currentLang === "ru" ? ["Б", "КБ", "МБ", "ГБ"] : ["B", "KB", "MB", "GB"];
  if (!b || b <= 0) return `0 ${units[0]}`;
  if (b < 1024) return `${b} ${units[0]}`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} ${units[1]}`;
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(2)} ${units[2]}`;
  return `${(b / (1024 * 1024 * 1024)).toFixed(2)} ${units[3]}`;
}

function fmtRate(bps) {
  if (!bps || bps <= 0) return "—";
  const units = currentLang === "ru" ? ["бит/с", "Кбит/с", "Мбит/с"] : ["bps", "Kbps", "Mbps"];
  if (bps < 1000) return `${bps} ${units[0]}`;
  if (bps < 1_000_000) return `${(bps / 1000).toFixed(0)} ${units[1]}`;
  return `${(bps / 1_000_000).toFixed(2)} ${units[2]}`;
}

function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString(currentLang === "ru" ? "ru-RU" : "en-GB", { hour12: false });
}

function riskBadge(risk) {
  const r = risk || "CLEAN";
  const cls = {
    CRITICAL: "badge-critical",
    HIGH: "badge-high",
    MEDIUM: "badge-medium",
    LOW: "badge-low",
    CLEAN: "badge-clean",
  }[r] || "badge-clean";
  const labels = currentLang === "ru"
    ? { CRITICAL: "КРИТИЧ", HIGH: "ВЫСОКИЙ", MEDIUM: "ВНИМАНИЕ", LOW: "НИЗКИЙ", CLEAN: "ЧИСТО" }
    : { CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", CLEAN: "CLEAN" };
  return `<span class="badge ${cls}">${labels[r] || r}</span>`;
}

function routeBadge(route) {
  if (!route) return "";
  let cls = "route-lan";
  if (route.startsWith("VPN")) cls = "route-vpn";
  else if (route.startsWith("WAN")) cls = "route-wan";
  return `<span class="badge ${cls}">${esc(route)}</span>`;
}

function sigHtml(flow) {
  if (!flow.is_local_pc) {
    return `<span style="color:var(--text-dim);">${esc(t("external_dev"))}</span>`;
  }
  if (flow.ghost_confirmed) {
    return `<span class="sig-ghost">⚠ GHOST SOCKET</span>`;
  }
  if (!flow.proc_name) {
    if (flow.dst_port === 53) {
      return `<span class="mono" style="color:var(--text-muted);"><span class="sig-valid">✓</span> OS DNS</span>`;
    }
    return `<span style="color:var(--text-dim);">${esc(t("short_socket"))}</span>`;
  }
  let icon = "•";
  let cls = "";
  if (flow.proc_sig_status === "Valid" || flow.proc_sig_status === "System") {
    icon = "✓";
    cls = "sig-valid";
  } else if (flow.proc_sig_status === "NotSigned") {
    icon = "⚠";
    cls = "sig-unsigned";
  }
  const title = esc((flow.proc_exe || "") + (flow.proc_sig_signer ? ` | ${flow.proc_sig_signer}` : ""));
  return `<span class="mono" title="${title}"><span class="${cls}">${icon}</span> ${esc(flow.proc_name)} <span style="color:var(--text-dim);">(${flow.pid ?? ""})</span></span>`;
}

function switchTab(tabId, btnEl) {
  document.querySelectorAll("main .tab-pane").forEach((el) => el.classList.remove("active"));
  document.querySelectorAll("main .tabs .tab-btn").forEach((el) => el.classList.remove("active"));
  const target = document.getElementById(tabId);
  if (target) target.classList.add("active");
  if (btnEl) btnEl.classList.add("active");
}

function filterByDevice(ip) {
  const sel = document.getElementById("filterDevice");
  if (sel) {
    sel.value = ip;
    const firstBtn = document.querySelector('.tab-btn[data-tab="tab-flows"]');
    switchTab("tab-flows", firstBtn);
    renderAll();
  }
}

async function quickSwitchMode(mode) {
  knownDevices.clear();
  const sel = document.getElementById("filterDevice");
  if (sel) sel.innerHTML = `<option value="ALL">${esc(t("opt_all_devices"))}</option>`;
  await fetch("/api/mode", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode }),
  });
}

async function toggleCapture() {
  if (!latestSnap) return;
  const endpoint = latestSnap.status.capturing ? "/api/capture/stop" : "/api/capture/start";
  await fetch(endpoint, { method: "POST" });
}

async function toggleIdleWatch() {
  await fetch("/api/idle-watch/toggle", { method: "POST" });
}

async function clearSession() {
  await fetch("/api/clear", { method: "POST" });
}

function downloadPcap() {
  window.location.href = "/api/pcap/download";
}

function downloadReport() {
  window.location.href = "/api/report/markdown";
}

async function handlePcapUpload(ev) {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  try {
    const buf = await file.arrayBuffer();
    const res = await fetch("/api/pcap/import", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: buf,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert(`PCAP import error: ${err.detail || res.statusText}`);
    }
  } finally {
    ev.target.value = "";
  }
}

async function updateFeeds() {
  const btn = document.getElementById("btnUpdateFeeds");
  btn.disabled = true;
  const origHtml = btn.innerHTML;
  btn.innerText = t("btn_updating_feeds");
  try {
    await fetch("/api/feeds/update", { method: "POST" });
  } finally {
    btn.innerHTML = origHtml;
    btn.disabled = false;
  }
}

// ------------------------------------------------------------------
// Router Wizard & AI Setup Prompt Generator
// ------------------------------------------------------------------
function openRouterModal() {
  if (latestSnap && latestSnap.status) {
    document.getElementById("inpRouterHost").value = latestSnap.status.router_host || "192.168.1.1";
    document.getElementById("inpRouterPort").value = latestSnap.status.router_port || 22;
    document.getElementById("inpRouterUser").value = latestSnap.status.router_user || "root";
    document.getElementById("inpRouterIface").value = latestSnap.status.router_iface || "br-lan";
    document.getElementById("inpAiRouterIp").value = latestSnap.status.router_host || "192.168.1.1";
  }
  refreshAiPrompt();
  document.getElementById("routerModalBackdrop").style.display = "block";
  document.getElementById("routerModal").style.display = "block";
}

function closeRouterModal() {
  document.getElementById("routerModalBackdrop").style.display = "none";
  document.getElementById("routerModal").style.display = "none";
}

function switchModalTab(which) {
  const isConn = which === "connect";
  document.getElementById("mPaneConnect").style.display = isConn ? "block" : "none";
  document.getElementById("mPaneAi").style.display = isConn ? "none" : "block";
  document.getElementById("mTabConnectBtn").className = isConn ? "tab-btn active" : "tab-btn";
  document.getElementById("mTabAiBtn").className = !isConn ? "tab-btn active" : "tab-btn";
  if (!isConn) refreshAiPrompt();
}

function refreshAiPrompt() {
  const el = document.getElementById("aiPromptTextarea");
  if (!el) return;
  const model = (document.getElementById("inpAiRouterModel")?.value || "OpenWrt / Linux Router").trim();
  const rip = (document.getElementById("inpAiRouterIp")?.value || "192.168.1.1").trim();
  const osName = (latestSnap && latestSnap.status && latestSnap.status.os_name) || "Windows / Linux / macOS";

  if (currentLang === "ru") {
    el.value = `Помоги мне безопасно подключить мой роутер к open-source системе сетевой защиты Aegis (Out-of-Band NGFW & Anti-Rootkit Shield).

Мои данные:
- Модель роутера / прошивка: ${model}
- Локальный IP роутера: ${rip}
- Моя рабочая ОС: ${osName}

Как работает Aegis:
Aegis НЕ требует установки тяжёлых агентов или фоновых демонов на роутер (0% фоновой нагрузки). При запуске с компьютера Aegis подключается к роутеру по SSH-ключу (BatchMode=yes) и запускает поток заголовков пакетов:
tcpdump -i <LAN_INTERFACE> -nn -U -s 1514 -w - 'not (host ${rip} and port 22)'

Дай мне чёткую пошаговую инструкцию конкретно под мой роутер (${model}):
1. Как включить SSH (только для локальной сети LAN, без доступа из WAN!).
2. Как сгенерировать SSH-ключ Ed25519 на моей ОС (${osName}) и добавить публичный ключ на роутер (чтобы вход работал без пароля).
3. Как установить лёгкий пакет tcpdump (например tcpdump-mini на OpenWrt / Entware на Keenetic или ASUS-Merlin / apt на Linux) с минимальным расходом памяти.
4. Как узнать точное имя локального сетевого моста роутера (например br-lan, br0, eth0), через который проходит трафик всех домашних устройств.
5. Команду проверки с моего компьютера, что SSH и tcpdump готовы, и итоговую команду запуска:
   aegis --router ${rip} --iface <LAN_INTERFACE> --open-browser`;
  } else {
    el.value = `Help me safely connect my router to the open-source Aegis Digital Shield (Out-of-Band NGFW, L7 DPI & Anti-Rootkit SOC).

My environment:
- Router model / firmware: ${model}
- Router LAN IP: ${rip}
- My workstation OS: ${osName}

How Aegis works:
Aegis installs ZERO background daemons on the router (0% idle CPU/RAM). When active on my computer, Aegis connects over key-based SSH (BatchMode=yes) and streams packet headers on demand via:
tcpdump -i <LAN_INTERFACE> -nn -U -s 1514 -w - 'not (host ${rip} and port 22)'

Please give me a safe, exact step-by-step guide tailored to my router (${model}):
1. How to enable SSH strictly on the LAN interface (never exposed to WAN).
2. How to generate an Ed25519 SSH key on ${osName} and install the public key onto the router for passwordless login.
3. How to install lightweight tcpdump (e.g., tcpdump-mini on OpenWrt, Entware tcpdump on Keenetic/ASUS-Merlin, or native package on UniFi/Linux).
4. How to verify the exact LAN bridge interface name (e.g., br-lan, br0, eth0) carrying local network traffic.
5. A quick verification command from my workstation and the final Aegis launch command:
   aegis --router ${rip} --iface <LAN_INTERFACE> --open-browser`;
  }
}

async function copyAiPrompt() {
  const el = document.getElementById("aiPromptTextarea");
  if (!el) return;
  await navigator.clipboard.writeText(el.value);
  const msg = document.getElementById("copyConfirmMsg");
  msg.innerText = currentLang === "ru" ? "✓ Промпт скопирован! Вставьте его в любой ИИ-чат." : "✓ Copied! Paste into ChatGPT, Claude, or Gemini.";
  setTimeout(() => { msg.innerText = ""; }, 3500);
}

function _getRouterFormPayload() {
  return {
    router_host: document.getElementById("inpRouterHost").value.trim(),
    router_port: parseInt(document.getElementById("inpRouterPort").value, 10) || 22,
    router_user: document.getElementById("inpRouterUser").value.trim() || "root",
    router_iface: document.getElementById("inpRouterIface").value.trim() || "br-lan",
    ssh_key_path: document.getElementById("inpRouterKey").value.trim(),
  };
}

async function testRouterDiagnostics() {
  const box = document.getElementById("routerDiagBox");
  box.style.display = "block";
  box.innerHTML = `<span style="color:var(--cyan);">⏳ Testing SSH & tcpdump...</span>`;
  const res = await fetch("/api/router/diagnose", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(_getRouterFormPayload()),
  });
  const d = await res.json();
  if (d.ok) {
    box.innerHTML = `
      <div style="color:var(--emerald);font-weight:700;">✓ Gateway Ready for Tier 2 Network Shield!</div>
      <div>OS: ${esc(d.router_os)} • Firewall: ${esc(d.firewall_backend)} • tcpdump: ${esc(d.tcpdump_path)}</div>
      <div>Available interfaces: ${esc((d.available_ifaces || []).join(", "))}</div>
    `;
  } else {
    box.innerHTML = `
      <div style="color:var(--crimson);font-weight:700;">✗ Check Failed</div>
      <div style="color:#fca5a5;">${esc(d.error || "Unknown error")}</div>
      ${d.available_ifaces?.length ? `<div style="margin-top:4px;color:var(--text-muted);">Detected interfaces: ${esc(d.available_ifaces.join(", "))}</div>` : ""}
    `;
  }
}

async function connectRouterLive() {
  const box = document.getElementById("routerDiagBox");
  box.style.display = "block";
  box.innerHTML = `<span style="color:var(--cyan);">⏳ Connecting & activating Tier 2 stream...</span>`;
  const res = await fetch("/api/router/connect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(_getRouterFormPayload()),
  });
  const d = await res.json();
  if (d.connected) {
    knownDevices.clear();
    closeRouterModal();
  } else {
    box.innerHTML = `<div style="color:var(--crimson);font-weight:700;">✗ ${esc(d.error || "Connection failed")}</div>`;
  }
}

// ------------------------------------------------------------------
// Active Shield & Router Audit Actions
// ------------------------------------------------------------------
async function runRouterAudit() {
  const btn = document.getElementById("btnRunAudit");
  btn.disabled = true;
  const cont = document.getElementById("routerAuditContainer");
  cont.innerHTML = `<div class="mono" style="color:var(--cyan);">⏳ Running read-only SSH security posture audit...</div>`;
  try {
    const res = await fetch("/api/router/audit", { method: "POST" });
    const d = await res.json();
    if (!d.ok) {
      cont.innerHTML = `<div style="color:#fca5a5;">✗ ${esc(d.error || "Router unreachable")}</div>`;
      return;
    }
    renderRouterAuditBox(d);
  } finally {
    btn.disabled = false;
  }
}

function renderRouterAuditBox(audit) {
  const cont = document.getElementById("routerAuditContainer");
  if (!cont) return;
  if (!audit || !audit.ok) {
    cont.innerHTML = `<div style="color:var(--text-muted);font-size:12px;">${esc(t("audit_hint"))}</div>`;
    return;
  }
  const col = audit.score >= 85 ? "var(--emerald)" : audit.score >= 65 ? "var(--amber)" : "var(--crimson)";
  const rows = (audit.checks || [])
    .map((c) => {
      const b = c.status === "PASS" ? "badge-clean" : c.status === "WARN" ? "badge-high" : "badge-low";
      return `
        <div style="display:flex;justify-content:space-between;gap:10px;padding:6px 0;border-bottom:1px solid rgba(30,43,66,0.5);">
          <div><strong>${esc(c.title)}</strong><div style="color:var(--text-muted);font-size:11.5px;">${esc(c.detail)}</div></div>
          <div><span class="badge ${b}">${esc(c.status)}</span></div>
        </div>`;
    })
    .join("");
  cont.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <div><strong>${esc(audit.router_os)}</strong></div>
      <div class="mono" style="font-size:16px;font-weight:700;color:${col};">Grade ${esc(audit.grade)} (${audit.score}/100)</div>
    </div>
    ${rows}
  `;
}

async function blockIpOnRouter(ip, reason) {
  if (!confirm(`Block all LAN traffic to external IP ${ip} on the router firewall (ephemeral RAM rule)?`)) return;
  const res = await fetch("/api/shield/block-ip", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, reason }),
  });
  const d = await res.json().catch(() => ({}));
  alert(res.ok ? d.message : `Block failed: ${d.detail || res.statusText}`);
}

async function manualBlockRemoteIp() {
  const ip = document.getElementById("manualBlockIp").value.trim();
  if (!ip) return;
  await blockIpOnRouter(ip, "Manual Block from Network Control Tab");
  document.getElementById("manualBlockIp").value = "";
}

async function quarantineLanHost(lanIp) {
  if (!confirm(`Quarantine LAN device ${lanIp} from internet access via router firewall?`)) return;
  const res = await fetch("/api/shield/quarantine-host", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ lan_ip: lanIp, reason: "SOC Quarantine" }),
  });
  const d = await res.json().catch(() => ({}));
  alert(res.ok ? d.message : `Quarantine failed: ${d.detail || res.statusText}`);
}

async function flushRouterRules() {
  const res = await fetch("/api/shield/flush-rules", { method: "POST" });
  const d = await res.json().catch(() => ({}));
  alert(res.ok ? d.message : `Error: ${d.detail || res.statusText}`);
}

async function killLocalProcess(pid, procName) {
  if (!confirm(`Terminate local process ${procName} (PID ${pid}) on this computer?`)) return;
  const res = await fetch("/api/shield/kill-pid", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pid }),
  });
  const d = await res.json().catch(() => ({}));
  alert(res.ok ? d.message : `Could not terminate PID ${pid}: ${d.detail || res.statusText}`);
}

// ------------------------------------------------------------------
// Canvas Throughput Oscilloscope & Dashboard Renderers
// ------------------------------------------------------------------
function drawTrafficChart(series) {
  const canvas = document.getElementById("trafficCanvas");
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width <= 0) return;
  if (canvas.width !== Math.floor(rect.width * dpr) || canvas.height !== Math.floor(rect.height * dpr)) {
    canvas.width = Math.floor(rect.width * dpr);
    canvas.height = Math.floor(rect.height * dpr);
  }
  const ctx = canvas.getContext("2d");
  ctx.save();
  ctx.scale(dpr, dpr);
  const w = rect.width;
  const h = rect.height;
  ctx.clearRect(0, 0, w, h);

  ctx.strokeStyle = "rgba(44, 64, 99, 0.35)";
  ctx.lineWidth = 1;
  for (let i = 1; i <= 2; i++) {
    const y = (h / 3) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  if (!series || series.length < 2) {
    ctx.restore();
    return;
  }

  let maxVal = 0.5;
  for (const pt of series) {
    if (pt.down_mbps > maxVal) maxVal = pt.down_mbps;
    if (pt.up_mbps > maxVal) maxVal = pt.up_mbps;
    if (pt.wan_mbps > maxVal) maxVal = pt.wan_mbps;
  }
  maxVal *= 1.15;

  const maxPts = 90;
  const stepX = w / (maxPts - 1);
  const startX = w - (series.length - 1) * stepX;

  function plotLine(key, stroke, fill) {
    ctx.beginPath();
    series.forEach((pt, idx) => {
      const x = startX + idx * stepX;
      const y = h - (pt[key] / maxVal) * (h - 6) - 2;
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 1.8;
    ctx.stroke();

    if (fill) {
      ctx.lineTo(startX + (series.length - 1) * stepX, h);
      ctx.lineTo(startX, h);
      ctx.closePath();
      ctx.fillStyle = fill;
      ctx.fill();
    }
  }

  plotLine("down_mbps", "#22d3ee", "rgba(34, 211, 238, 0.14)");
  plotLine("wan_mbps", "#10b981", null);
  plotLine("up_mbps", "#a855f7", "rgba(168, 85, 247, 0.10)");

  ctx.fillStyle = "#8b9bb4";
  ctx.font = "10px Consolas, monospace";
  const unit = currentLang === "ru" ? "Мбит/с" : "Mbps";
  const pkLbl = currentLang === "ru" ? "Пик" : "Peak";
  ctx.fillText(`${pkLbl}: ${maxVal.toFixed(1)} ${unit}`, 6, 11);
  ctx.restore();
}

function renderAll() {
  if (!latestSnap) return;
  const s = latestSnap.status;
  const k = latestSnap.kpis;
  const isRu = currentLang === "ru";

  // Mode segmented buttons & Tier pill
  document.getElementById("btnModeSystem").className = s.mode === "system" ? "seg-btn active" : "seg-btn";
  document.getElementById("btnModeRouter").className = s.mode === "router" ? "seg-btn active" : "seg-btn";
  document.getElementById("btnModeDemo").className = s.mode === "demo" ? "seg-btn active" : "seg-btn";

  const tierPill = document.getElementById("tierBadgePill");
  if (s.mode === "router") {
    tierPill.className = "tier-pill tier2";
    tierPill.innerText = isRu ? "УРОВЕНЬ 2: СЕТЬ РОУТЕРА" : "TIER 2: ROUTER LAN";
  } else if (s.mode === "demo") {
    tierPill.className = "tier-pill tier2";
    tierPill.innerText = "TIER 2: DEMO";
  } else if (s.mode === "pcap") {
    tierPill.className = "tier-pill";
    tierPill.innerText = "FORENSIC PCAP";
  } else {
    tierPill.className = "tier-pill";
    tierPill.innerText = isRu ? "УРОВЕНЬ 1: СИСТЕМА ОС" : "TIER 1: SYSTEM OS";
  }

  document.getElementById("tierUpgradeStrip").style.display = s.mode === "system" ? "flex" : "none";

  const rkBox = document.getElementById("rootkitExplainBox");
  if (rkBox) {
    rkBox.innerHTML = (s.mode === "router" || s.mode === "demo") ? t("rootkit_explain_t2") : t("rootkit_explain_t1");
  }

  const noticeBanner = document.getElementById("noticeBanner");
  if (s.fallback_notice) {
    noticeBanner.style.display = "block";
    noticeBanner.innerText = `ℹ ${s.fallback_notice}`;
  } else {
    noticeBanner.style.display = "none";
  }

  const pill = document.getElementById("captureStatusPill");
  const pillTxt = document.getElementById("captureStatusText");
  const capBtn = document.getElementById("btnCaptureToggle");
  const errBanner = document.getElementById("errorBanner");

  if (s.error) {
    pill.className = "status-pill error";
    pillTxt.innerText = t("status_error");
    errBanner.style.display = "block";
    errBanner.innerText = s.error;
  } else if (s.capturing) {
    pill.className = "status-pill";
    pillTxt.innerText =
      s.mode === "demo" ? t("status_demo") : s.mode === "system" ? t("status_system") : t("status_router");
    errBanner.style.display = "none";
  } else {
    pill.className = "status-pill paused";
    pillTxt.innerText = s.mode === "pcap" ? t("status_pcap") : t("status_paused");
    errBanner.style.display = "none";
  }
  capBtn.innerText = s.capturing ? t("btn_pause") : t("btn_resume");

  const hostIps = (s.local_pc_ips || []).join(", ") || "127.0.0.1";
  if (s.mode === "system") {
    document.getElementById("routerMetaSub").innerText = isRu
      ? `Узел: ${s.hostname} (${s.os_name} • ${hostIps}) • Сокетов ядра ОС: ${s.os_sockets_polled} (${s.poll_ms} мс)`
      : `Host: ${s.hostname} (${s.os_name} • ${hostIps}) • OS Kernel Sockets: ${s.os_sockets_polled} (${s.poll_ms} ms)`;
  } else {
    document.getElementById("routerMetaSub").innerText = isRu
      ? `Шлюз: ${s.router_user}@${s.router_host} (${s.router_iface}) • Этот ПК (${s.os_name}): ${hostIps} • Сокетов ОС: ${s.os_sockets_polled} • Буфер PCAP: ${s.pcap_buffered_pkts}`
      : `Gateway: ${s.router_user}@${s.router_host} (${s.router_iface}) • Host (${s.os_name}): ${hostIps} • OS Sockets: ${s.os_sockets_polled} • PCAP Ring: ${s.pcap_buffered_pkts}`;
  }

  const idleBtn = document.getElementById("btnIdleWatch");
  if (s.idle_watch) {
    idleBtn.className = "btn btn-idle-active";
    idleBtn.innerText = t("btn_idle_on");
  } else {
    idleBtn.className = "btn";
    idleBtn.innerText = `🛡 ${t("btn_idle_off")}`;
  }

  // Shield Score KPI
  const sc = k.shield_score ?? 100;
  const scEl = document.getElementById("kpiShieldScore");
  scEl.innerText = `${sc} / 100`;
  scEl.style.color = sc >= 85 ? "var(--emerald)" : sc >= 60 ? "var(--amber)" : "var(--crimson)";
  document.getElementById("kpiShieldSub").innerText =
    s.mode === "router"
      ? (isRu ? "Уровень 2 • Вся сеть + Анти-Руткит" : "Tier 2 • Whole-LAN + Anti-Rootkit")
      : s.mode === "system"
      ? (isRu ? "Уровень 1 • Защита ОС активна" : "Tier 1 • Host OS Shield Active")
      : s.tier_label;

  const spdUnit = isRu ? "Мбит/с" : "Mbps";
  document.getElementById("kpiSpeed").innerText = `↓ ${k.down_mbps.toFixed(2)} / ↑ ${k.up_mbps.toFixed(2)} ${spdUnit}`;
  document.getElementById("kpiTotals").innerText = `${isRu ? "Всего" : "Total"}: ↓ ${fmtBytes(k.total_bytes_in)} • ↑ ${fmtBytes(k.total_bytes_out)}`;
  document.getElementById("kpiFlows").innerText = `${k.active_flows} ${isRu ? "потоков" : "flows"}`;
  document.getElementById("kpiPackets").innerText = `${isRu ? "Пакетов" : "Packets"}: ${k.total_packets.toLocaleString()}`;

  const ghostCard = document.getElementById("kpiGhostCard");
  const ghostVal = document.getElementById("kpiGhost");
  if (k.ghost_sockets > 0) {
    ghostCard.className = "kpi-card alert-critical";
    ghostVal.style.color = "var(--crimson)";
    ghostVal.innerText = `⚠ ${k.ghost_sockets} GHOST SOCKET!`;
  } else {
    ghostCard.className = "kpi-card";
    ghostVal.style.color = "var(--emerald)";
    ghostVal.innerText = isRu ? "0 скрытых (Чисто)" : "0 hidden (Clean)";
  }
  document.getElementById("kpiVerified").innerText = isRu
    ? `Сверено сокетов ОС: ${k.verified_pc_flows}`
    : `Verified OS sockets: ${k.verified_pc_flows}`;

  const intel = latestSnap.intel || {};
  const alertsCard = document.getElementById("kpiAlertsCard");
  alertsCard.className = k.alerts_critical > 0 ? "kpi-card alert-critical" : "kpi-card";
  document.getElementById("kpiAlerts").innerText = isRu
    ? `${k.alerts_critical} КРИТ • ${k.alerts_high} ВЫС`
    : `${k.alerts_critical} CRIT • ${k.alerts_high} HIGH`;
  document.getElementById("kpiAlertsMed").innerText =
    `Med: ${k.alerts_medium} • IOC: ${(intel.total_ioc || 0).toLocaleString()}`;

  document.getElementById("badgeFlows").innerText = k.active_flows;
  document.getElementById("badgeProcs").innerText = (latestSnap.pc_processes || []).length;
  document.getElementById("badgeBlocks").innerText = k.active_blocks || 0;
  const totAlerts = (latestSnap.alerts || []).length;
  const bAlerts = document.getElementById("badgeAlerts");
  bAlerts.innerText = totAlerts;
  bAlerts.className = (k.alerts_critical + k.alerts_high) > 0 ? "tab-badge danger" : "tab-badge";

  drawTrafficChart(latestSnap.timeseries);

  const devSelect = document.getElementById("filterDevice");
  for (const d of latestSnap.devices || []) {
    if (!knownDevices.has(d.ip)) {
      knownDevices.add(d.ip);
      const opt = document.createElement("option");
      opt.value = d.ip;
      opt.textContent = `${d.device} (${d.ip})${d.is_local_pc ? ` ★ ${t("this_host")}` : ""}`;
      devSelect.appendChild(opt);
    }
  }

  if (!document.getElementById("chkFreezeTable").checked) {
    renderFlowsTable(latestSnap.flows || []);
  }
  renderRootkitTable(latestSnap.pc_processes || []);
  renderDpiTab(latestSnap.top_apps || [], latestSnap.devices || [], latestSnap.recent_dns || []);
  renderAlertsTable(latestSnap.alerts || []);
  renderRulesTable(latestSnap.active_rules || []);
  renderRouterAuditBox(latestSnap.router_audit);
  renderFeedsTable(intel.feeds || []);
}

function renderFlowsTable(flows) {
  const q = (document.getElementById("filterSearch").value || "").trim().toLowerCase();
  const fDev = document.getElementById("filterDevice").value;
  const fRoute = document.getElementById("filterRoute").value;
  const fRisk = document.getElementById("filterRisk").value;

  const filtered = flows.filter((f) => {
    if (fDev !== "ALL" && f.src_ip !== fDev) return false;
    if (fRoute !== "ALL" && !f.route.startsWith(fRoute)) return false;
    if (fRisk === "ALERTS" && f.risk === "CLEAN") return false;
    if (fRisk === "NODNS" && f.domain) return false;
    if (fRisk === "GHOST" && !f.ghost_confirmed) return false;
    if (q) {
      const hay = `${f.src_device} ${f.src_ip} ${f.dst_ip} ${f.dst_port} ${f.domain} ${f.app} ${f.category} ${f.proc_name} ${f.ja3} ${f.proc_sha256 || ""} ${f.org} ${f.asn}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const tbody = document.getElementById("flowsTbody");
  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:24px;">${esc(t("no_flows"))}</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered
    .map((f) => {
      const rowCls = f.risk === "CRITICAL" ? "row-critical" : f.risk === "HIGH" ? "row-high" : "";
      const domHtml = f.domain
        ? `<span class="mono" style="color:var(--text-main);">${esc(f.domain)}</span> <span style="color:var(--text-dim);font-size:10.5px;">[${esc(f.domain_source)}]</span>`
        : f.seen_syn
        ? `<span style="color:var(--amber);font-size:11px;">${esc(t("direct_ip_tag"))}</span>`
        : `<span style="color:var(--text-dim);font-size:11px;">${esc(t("preexisting_tag"))}</span>`;
      const orgTxt = f.org ? `${f.cc ? f.cc + " • " : ""}${f.org.slice(0, 28)}` : f.cc || "";
      const volTxt = (f.bytes_in + f.bytes_out) > 0
        ? `↓ ${fmtBytes(f.bytes_in)} / ↑ ${fmtBytes(f.bytes_out)}`
        : `<span style="color:var(--text-dim);">${esc(f.tls_version || "OS Socket")}</span>`;
      return `
        <tr class="${rowCls}" onclick="openFlowDrawer('${esc(f.id)}')">
          <td>${riskBadge(f.risk)}</td>
          <td>
            <div style="font-weight:600;">${esc(f.src_device)}</div>
            <div class="mono" style="color:var(--text-dim);font-size:10.5px;">${esc(f.src_ip)}:${f.src_port}</div>
          </td>
          <td>${sigHtml(f)}</td>
          <td>
            <div style="font-weight:600;color:var(--cyan);">${esc(f.app)}</div>
            <div style="color:var(--text-dim);font-size:10.5px;">${esc(f.l7_proto)} • ${esc(f.category)}</div>
          </td>
          <td>${domHtml}</td>
          <td>
            <div class="mono">${esc(f.dst_ip)}:${f.dst_port}</div>
            <div style="color:var(--text-muted);font-size:10.5px;">${esc(orgTxt)}</div>
          </td>
          <td>${routeBadge(f.route)}</td>
          <td class="mono">${volTxt}</td>
          <td class="mono" style="color:${f.rate_bps > 0 ? "var(--cyan)" : "var(--text-dim)"};">${fmtRate(f.rate_bps)}</td>
        </tr>`;
    })
    .join("");
}

function renderRootkitTable(procs) {
  const tbody = document.getElementById("procsTbody");
  const isRu = currentLang === "ru";
  document.getElementById("pcAuditMeta").innerText = isRu
    ? `Активных процессов в сети: ${procs.length}`
    : `Active host processes: ${procs.length}`;
  if (!procs.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:24px;">${esc(t("waiting_procs"))}</td></tr>`;
    return;
  }

  tbody.innerHTML = procs
    .map((p) => {
      let sigCol = `<span style="color:var(--text-muted);">${esc(p.sig_status)}</span>`;
      if (p.ghost) {
        sigCol = `<span class="sig-ghost">🚨 GHOST SOCKET</span>`;
      } else if (p.sig_status === "Valid" || p.sig_status === "System") {
        sigCol = `<span class="sig-valid">✓ ${esc(p.sig_signer || "Verified")}</span>`;
      } else if (p.sig_status === "NotSigned") {
        sigCol = `<span class="sig-unsigned">⚠ NotSigned</span>`;
      }
      const shaShort = p.sha256 ? `${p.sha256.slice(0, 12)}…` : "—";
      return `
        <tr class="${p.ghost ? "row-critical" : ""}">
          <td class="mono">${p.pid || "—"}</td>
          <td style="font-weight:700;">${esc(p.proc_name)}</td>
          <td>${sigCol}</td>
          <td class="mono" style="color:var(--text-muted);" title="${esc(p.sha256 || "")}">${esc(shaShort)}</td>
          <td class="mono" style="color:var(--text-muted);max-width:360px;overflow:hidden;text-overflow:ellipsis;" title="${esc(p.proc_exe)}">${esc(p.proc_exe || "—")}</td>
          <td class="mono">${p.flows_count}</td>
          <td class="mono" style="color:var(--cyan);">${esc((p.sample_targets || []).join(", "))}</td>
        </tr>`;
    })
    .join("");
}

function renderDpiTab(apps, devices, dnsList) {
  const appsEl = document.getElementById("appsContainer");
  const maxB = apps.length ? Math.max(apps[0].bytes, 1) : 1;
  const isSystem = latestSnap?.status?.mode === "system";
  appsEl.innerHTML = apps.length
    ? apps
        .map((a) => {
          const pct = Math.max(3, Math.round((a.bytes / maxB) * 100));
          const rightLbl = isSystem ? `${a.flows} sockets` : fmtBytes(a.bytes);
          return `
            <div class="bar-row">
              <div class="bar-top">
                <span><strong>${esc(a.app)}</strong> <span style="color:var(--text-dim);">(${esc(a.category)} • ${a.flows})</span></span>
                <span class="mono">${esc(rightLbl)}</span>
              </div>
              <div class="bar-track"><div class="bar-fill" style="width:${pct}%;"></div></div>
            </div>`;
        })
        .join("")
    : `<div style="padding:20px;color:var(--text-muted);text-align:center;">—</div>`;

  const devTbody = document.getElementById("devicesTbody");
  devTbody.innerHTML = devices
    .map(
      (d) => `
      <tr onclick="filterByDevice('${esc(d.ip)}')">
        <td style="font-weight:600;">${esc(d.device)} ${d.is_local_pc ? `<span class="badge badge-low">${esc(t("this_host"))}</span>` : ""}</td>
        <td class="mono">${esc(d.ip)}</td>
        <td class="mono" style="color:var(--text-muted);">${esc(d.mac || "—")}</td>
        <td class="mono">${d.flows}</td>
        <td class="mono">↓ ${fmtBytes(d.bytes_in)} / ↑ ${fmtBytes(d.bytes_out)}</td>
        <td>${d.alerts > 0 ? `<span class="badge badge-high">${d.alerts}</span>` : `<span style="color:var(--emerald);">0</span>`}</td>
      </tr>`
    )
    .join("");

  const dnsTbody = document.getElementById("dnsTbody");
  dnsTbody.innerHTML = dnsList.length
    ? dnsList
        .map(
          (q) => `
        <tr>
          <td class="mono" style="color:var(--text-muted);">${fmtTime(q.ts)}</td>
          <td>${esc(q.device)} <span class="mono" style="color:var(--text-dim);">(${esc(q.client_ip)})</span></td>
          <td class="mono" style="color:var(--cyan);">${esc(q.qname)}</td>
          <td class="mono" style="color:var(--text-muted);">${esc((q.ips || []).join(", ") || "—")}</td>
        </tr>`
        )
        .join("")
    : `<tr><td colspan="4" style="padding:18px;text-align:center;color:var(--text-muted);">${esc(t("waiting_dns"))}</td></tr>`;
}

function renderAlertsTable(alerts) {
  const tbody = document.getElementById("alertsTbody");
  const isRu = currentLang === "ru";
  if (!alerts.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--emerald);padding:26px;">${esc(t("no_alerts"))}</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts
    .map((a) => {
      const title = isRu && a.title_ru ? a.title_ru : a.title;
      const desc = isRu && a.description_ru ? a.description_ru : a.description;
      return `
      <tr class="${a.severity === "CRITICAL" ? "row-critical" : a.severity === "HIGH" ? "row-high" : ""}" onclick="${a.flow_id ? `openFlowDrawer('${esc(a.flow_id)}')` : ""}">
        <td class="mono">${fmtTime(a.ts)}</td>
        <td>${riskBadge(a.severity)}</td>
        <td class="mono">${esc(a.sig_id)}<div style="color:var(--text-dim);font-size:10px;">${esc(a.mitre)}</div></td>
        <td>
          <div style="font-weight:600;">${esc(a.src_device)}</div>
          <div class="mono" style="color:var(--text-muted);font-size:10.5px;">${esc(a.process_name || a.src_ip)}</div>
        </td>
        <td class="mono">${esc(a.domain || a.dst_ip)}:${a.dst_port}</td>
        <td style="white-space:normal;min-width:340px;">
          <div style="font-weight:700;margin-bottom:2px;">${esc(title)}</div>
          <div style="color:var(--text-muted);font-size:11.5px;">${esc(desc)}</div>
        </td>
      </tr>`;
    })
    .join("");
}

function renderRulesTable(rules) {
  const tbody = document.getElementById("rulesTbody");
  if (!tbody) return;
  if (!rules.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:20px;">${esc(t("no_rules"))}</td></tr>`;
    return;
  }
  tbody.innerHTML = rules
    .map(
      (r) => `
      <tr>
        <td class="mono" style="font-weight:700;color:#fca5a5;">${esc(r.target)}</td>
        <td><span class="badge badge-high">${esc(r.scope)}</span></td>
        <td class="mono">${esc(r.backend)}</td>
        <td style="color:var(--text-muted);">${esc(r.reason)}</td>
      </tr>`
    )
    .join("");
}

function renderFeedsTable(feeds) {
  const tbody = document.getElementById("feedsTbody");
  const isRu = currentLang === "ru";
  tbody.innerHTML = feeds
    .map((f) => {
      const st = f.online
        ? `<span class="badge badge-clean">${isRu ? "АКТИВНА" : "ONLINE"}</span>`
        : `<span class="badge badge-medium">${isRu ? "ОЖИДАЕТ" : "PENDING"}</span>`;
      const dt = f.updated_at ? new Date(f.updated_at * 1000).toLocaleString(isRu ? "ru-RU" : "en-GB") : "—";
      const fname = isRu && f.name_ru ? f.name_ru : f.name;
      return `
        <tr>
          <td>${st}</td>
          <td style="font-weight:600;">${esc(fname)}</td>
          <td class="mono">${(f.loaded_count || 0).toLocaleString()}</td>
          <td class="mono" style="color:var(--text-muted);">${esc(dt)}</td>
        </tr>`;
    })
    .join("");
}

async function openFlowDrawer(flowId) {
  if (!flowId) return;
  const isRu = currentLang === "ru";
  try {
    const res = await fetch(`/api/flow/${encodeURIComponent(flowId)}`);
    if (!res.ok) return;
    const f = await res.json();
    const g = f.geo || {};
    const fw = f.firewall_commands || {};
    const alertsHtml = (f.matched_alerts || []).length
      ? f.matched_alerts
          .map((a) => {
            const title = isRu && a.title_ru ? a.title_ru : a.title;
            const desc = isRu && a.description_ru ? a.description_ru : a.description;
            return `
          <div style="background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.4);border-radius:6px;padding:9px;margin-bottom:8px;">
            <div style="font-weight:700;color:#fca5a5;">[${esc(a.sig_id)}] ${esc(title)}</div>
            <div style="font-size:11.5px;color:var(--text-main);margin-top:4px;">${esc(desc)}</div>
          </div>`;
          })
          .join("")
      : `<div style="color:var(--emerald);margin-bottom:10px;">✓ ${isRu ? "Срабатываний сигнатур по этому потоку нет" : "No Threat Intel alerts triggered for this flow"}</div>`;

    const osintHtml = `
      <div class="osint-links">
        <a class="osint-link" href="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(f.dst_ip)}" target="_blank" rel="noopener">🔎 VirusTotal IP</a>
        <a class="osint-link" href="https://www.abuseipdb.com/check/${encodeURIComponent(f.dst_ip)}" target="_blank" rel="noopener">🛡 AbuseIPDB</a>
        ${f.proc_sha256 ? `<a class="osint-link" href="https://www.virustotal.com/gui/file/${encodeURIComponent(f.proc_sha256)}" target="_blank" rel="noopener">🧬 VirusTotal SHA-256</a>` : ""}
      </div>
    `;

    const isRouterMode = latestSnap?.status?.mode === "router";
    const actionBtns = [];
    if (f.is_local_pc && f.pid && f.pid > 4) {
      actionBtns.push(`<button class="btn btn-danger" onclick="killLocalProcess(${f.pid}, '${esc(f.proc_name)}')">🛑 ${isRu ? "Завершить процесс" : "Kill Process"} (PID ${f.pid})</button>`);
    }
    if (isRouterMode && g.cc !== "LAN") {
      actionBtns.push(`<button class="btn btn-danger" onclick="blockIpOnRouter('${esc(f.dst_ip)}', 'Blocked from Flow Drawer')">🚫 ${isRu ? "Блок IP на роутере" : "Block IP on Router"}</button>`);
    }
    if (isRouterMode && !f.is_local_pc) {
      actionBtns.push(`<button class="btn btn-danger" onclick="quarantineLanHost('${esc(f.src_ip)}')">🔒 ${isRu ? "Карантин устройства LAN" : "Quarantine LAN Host"}</button>`);
    }

    const actionsBlock = actionBtns.length
      ? `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">${actionBtns.join("")}</div>`
      : "";

    const fwBlock = fw.windows_powershell
      ? `
        <h4 style="margin:10px 0 6px;font-size:12.5px;color:var(--text-muted);">${isRu ? "Команды локального фаервола ОС (Copy & Run)" : "Host OS Firewall Block Commands"}</h4>
        <div class="kv-grid" style="grid-template-columns: 95px 1fr;">
          <div class="kv-key">PowerShell</div><div class="kv-val">${esc(fw.windows_powershell)}</div>
          <div class="kv-key">Linux nft</div><div class="kv-val">${esc(fw.linux_nftables)}</div>
          <div class="kv-key">macOS pf</div><div class="kv-val">${esc(fw.macos_pf)}</div>
        </div>`
      : "";

    document.getElementById("drawerContent").innerHTML = `
      ${alertsHtml}
      ${osintHtml}
      ${actionsBlock}
      <div class="kv-grid">
        <div class="kv-key">${isRu ? "Приложение / Категория" : "Application / Category"}</div><div class="kv-val" style="color:var(--cyan);font-weight:700;">${esc(f.app)} (${esc(f.category)})</div>
        <div class="kv-key">${isRu ? "Протокол L4 / L7" : "Protocol L4 / L7"}</div><div class="kv-val">${esc(f.proto)} / ${esc(f.l7_proto)}</div>
        <div class="kv-key">${isRu ? "Маршрут" : "Route"}</div><div class="kv-val">${routeBadge(f.route)}</div>
        <div class="kv-key">${isRu ? "Источник в LAN" : "Local Source"}</div><div class="kv-val">${esc(f.src_device)} (${esc(f.src_ip)}:${f.src_port}${f.src_mac ? ` • MAC ${esc(f.src_mac)}` : ""})</div>
        <div class="kv-key">${isRu ? "Удалённый узел" : "Remote Endpoint"}</div><div class="kv-val">${esc(f.dst_ip)}:${f.dst_port}</div>
        <div class="kv-key">${isRu ? "Страна / BGP ASN" : "Country / BGP ASN"}</div><div class="kv-val">${esc(g.cc || "—")} • ${esc(g.asn || "—")} • ${esc(g.org || "—")}</div>
        <div class="kv-key">${isRu ? "Домен (Источник)" : "Domain (Source)"}</div><div class="kv-val">${esc(f.domain || "—")} ${f.domain_source ? `[${esc(f.domain_source)}]` : ""}</div>
        <div class="kv-key">TLS SNI / State / ALPN</div><div class="kv-val">${esc(f.sni || "—")} | ${esc(f.tls_version || "—")} | ${esc(f.alpn || "—")}</div>
        <div class="kv-key">TLS JA3 MD5</div><div class="kv-val">${esc(f.ja3 || "—")}</div>
        <div class="kv-key">${isRu ? "Пакеты / Объём" : "Packets / Bytes"}</div><div class="kv-val">↓ ${f.packets_in} (${fmtBytes(f.bytes_in)}) / ↑ ${f.packets_out} (${fmtBytes(f.bytes_out)})</div>
      </div>

      <h4 style="margin:10px 0 8px;font-size:12.5px;color:var(--text-muted);">${isRu ? "Атрибуция процесса ОС и Цифровая подпись" : "Host OS Process Attribution & Binary Integrity"}</h4>
      <div class="kv-grid">
        <div class="kv-key">${isRu ? "Статус сверки" : "Verification"}</div><div class="kv-val">${f.ghost_confirmed ? '<span class="sig-ghost">🚨 GHOST SOCKET (HIDDEN FROM OS!)</span>' : f.is_local_pc ? '<span class="sig-valid">✓ Verified in OS Kernel Socket Table</span>' : (isRu ? "Другое устройство LAN" : "External LAN Device")}</div>
        <div class="kv-key">${isRu ? "Процесс / PID" : "Process / PID"}</div><div class="kv-val">${esc(f.proc_name || "—")} ${f.pid !== null ? `(PID ${f.pid}${f.proc_parent ? `, Parent: ${esc(f.proc_parent)}` : ""})` : ""}</div>
        <div class="kv-key">${isRu ? "Исполняемый файл" : "Executable"}</div><div class="kv-val">${esc(f.proc_exe || "—")}</div>
        <div class="kv-key">SHA-256</div><div class="kv-val">${esc(f.proc_sha256 || "—")}</div>
        <div class="kv-key">${isRu ? "Пользователь" : "User"}</div><div class="kv-val">${esc(f.proc_user || "—")}</div>
        <div class="kv-key">${isRu ? "Цифровая подпись" : "Code Signature"}</div><div class="kv-val">${esc(f.proc_sig_status || "—")} ${f.proc_sig_signer ? `(${esc(f.proc_sig_signer)})` : ""}</div>
      </div>
      ${fwBlock}
    `;
    document.getElementById("drawerBackdrop").style.display = "block";
    document.getElementById("flowDrawer").style.display = "block";
  } catch (e) {
    console.error(e);
  }
}

function closeDrawer() {
  document.getElementById("drawerBackdrop").style.display = "none";
  document.getElementById("flowDrawer").style.display = "none";
}

function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws`);
  ws.onmessage = (ev) => {
    try {
      latestSnap = JSON.parse(ev.data);
      if (!currentLang) {
        currentLang =
          latestSnap.status.default_lang ||
          (navigator.language && navigator.language.startsWith("ru") ? "ru" : "en");
        applyStaticTranslations();
      }
      renderAll();
    } catch (e) {
      console.error(e);
    }
  };
  ws.onclose = () => {
    setTimeout(connectWebSocket, 1500);
  };
}

window.addEventListener("DOMContentLoaded", () => {
  if (currentLang) applyStaticTranslations();
  connectWebSocket();
});
