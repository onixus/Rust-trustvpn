"use strict";
const $ = (s) => document.querySelector(s),
  esc = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
let state = {},
  page = "overview",
  loading = false,
  routeDirty = false;
const titles = {
  overview: "Обзор сети",
  users: "Пользователи",
  keys: "Ключи и устройства",
  routing: "Маршрутизация",
  updates: "Обновления",
  campaigns: "Рассылки",
  telegram: "Telegram",
  audit: "Журнал операций",
};
const labels = {
  queued: "В очереди",
  running: "Выполняется",
  success: "Выполнено",
  failed: "Ошибка",
  unknown: "Не подтверждено",
  active: "Активен",
  blocked: "Заблокирован",
  draft: "Черновик",
  accepted: "Принято провайдером",
  partial: "Частично",
  pending: "Ожидает",
  skipped: "Пропущено",
  sending: "Отправляется",
};
const pill = (s, t) =>
  `<span class="pill ${["failed", "blocked", "unknown"].includes(s) ? "red" : ["queued", "draft", "partial"].includes(s) ? "warn" : ["running", "pending"].includes(s) ? "blue" : ""}">${esc(t || labels[s] || s)}</span>`;
const heading = (title, sub, buttons = "") =>
  `<div class="heading"><div><div class="eyebrow">R-TRUSTTUNNEL / CONTROL PLANE</div><h1>${title}</h1><p class="subtitle">${sub}</p></div>${buttons}</div>`;
const table = (heads, rows) =>
  `<div class="table-wrap"><table><thead><tr>${heads.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.join("") || `<tr><td colspan="${heads.length}" class="empty">Пока нет данных</td></tr>`}</tbody></table></div>`;
const btn = (label, action, extra = "", cls = "") =>
  `<button class="${cls}" data-action="${action}" ${extra}>${label}</button>`;
const bytes = (n) =>
  n >= 1073741824
    ? (n / 1073741824).toFixed(1) + " GB"
    : (n / 1048576).toFixed(1) + " MB";
function notice(text, error = false) {
  $("#notice").textContent = text;
  $("#notice").classList.toggle("error", error);
}
async function api(path, data) {
  const r = await fetch("/console/api/" + path, {
    method: data === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": $("meta[name=csrf-token]").content,
    },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  let value;
  try {
    value = await r.json();
  } catch {
    throw Error("Сервис недоступен. Обновите состояние перед повтором.");
  }
  if (!r.ok) throw Error(value.detail || "Ошибка запроса");
  return value;
}
async function refresh(renderPage = true) {
  if (loading) return;
  loading = true;
  try {
    state = await api("state");
    $("#freshness").textContent =
      "Снимок · " + new Date(state.observed_at).toLocaleTimeString("ru");
    if (renderPage) render();
    if (state.error) notice(state.error, true);
  } catch (e) {
    notice(e.message, true);
    $("#freshness").textContent = "Нет связи";
  } finally {
    loading = false;
  }
}
function modal(title, html) {
  $("#modal-title").textContent = title;
  $("#modal-body").innerHTML = html;
  $("#modal").showModal();
}
async function job(action, data) {
  const result = await api("jobs", {
    action,
    data,
    confirm: true,
    request_id: crypto.randomUUID(),
  });
  $("#modal").close();
  notice("Операция поставлена в очередь. Результат появится в журнале.");
  await refresh();
  pollJob(result.id);
}
async function pollJob(id) {
  for (let i = 0; i < 100; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    await refresh(false);
    const j = state.jobs?.find((j) => j.id === id);
    if (j && !["queued", "running"].includes(j.state)) {
      let result = {};
      try {
        result = JSON.parse(j.result || "{}");
      } catch {}
      notice(result.message || labels[j.state], j.state !== "success");
      if (!routeDirty) render();
      return;
    }
  }
  notice("Операция ещё выполняется. Проверьте журнал позже.");
}
function confirmJob(title, description, action, data) {
  modal(
    title,
    `<p>${esc(description)}</p><div class="note">Изменение будет записано в журнал операций.</div><div class="actions"><button id="confirm-action" class="primary">Подтвердить</button></div>`,
  );
  $("#confirm-action").onclick = async () => {
    const b = $("#confirm-action");
    b.disabled = true;
    try {
      await job(action, data);
    } catch (e) {
      notice(e.message, true);
      $("#modal").close();
    }
  };
}
function overview() {
  const h = Array.isArray(state.hysteria_users) ? state.hysteria_users : [],
    u = state.users || [],
    r = state.routing || {},
    services = state.services || {};
  return (
    heading(
      "Вся сеть. Один пульт.",
      "Пользователи, доступ и выходные узлы вашей VPN-инфраструктуры.",
      pill("active", "ONIXUS-RF"),
    ) +
    `<div class="stats"><div class="stat"><label>УЧЁТНЫЕ ЗАПИСИ</label><strong>${u.length + h.length}</strong><small>${u.length} TrustTunnel · ${h.length} Hysteria</small></div><div class="stat"><label>КЛЮЧИ TRUSTTUNNEL</label><strong>${(state.keys || []).filter((k) => !k.revoked_at).length}</strong><small>Действующие учётные данные</small></div><div class="stat"><label>ВЫХОДЫ HYSTERIA</label><strong>${r.exits?.length ?? "—"}</strong><small>Выбран: ${esc(r.selected || "неизвестно")}</small></div><div class="stat"><label>УСТРОЙСТВА ПОРТАЛА</label><strong>${(state.devices || []).filter((d) => !d.revoked_at).length}</strong><small>Регистрации клиентов</small></div></div><div class="grid"><div class="card"><h2>Карта выходных узлов</h2><p class="subtitle">Текущая политика Hysteria 2</p><div class="topology"><div class="node current"><strong>VPN-сервер</strong><small>Входящий VPN</small>${pill("active", "INGRESS")}</div><div class="flow">→</div><div class="exit-stack">${(r.exits || []).map((e) => `<div class="node ${e.id === r.selected ? "current" : ""}"><strong>${esc(e.host)}</strong><small>${esc(e.via)}</small>${pill(e.id === r.selected ? "active" : "queued", e.id === r.selected ? "ВЫБРАН" : "ДОСТУПЕН ДЛЯ ВЫБОРА")}</div>`).join("") || '<p class="error">Нет данных агента</p>'}</div></div><div class="note">TrustTunnel и сам сервер выходят напрямую. Исключения Hysteria обрабатываются раньше общего маршрута. Доступность выходов проверяется отдельно.</div>${btn("Управлять маршрутами →", "navigate", 'data-target="routing"', "subtle")}</div><div class="stack"><div class="card"><h2>Сервисы</h2>${[
      ["Hysteria 2", "hysteria", "QUIC / UDP · 443"],
      ["TrustTunnel", "trusttunnel", "HTTP/2 + QUIC · 8443"],
    ]
      .map(
        ([n, k, d]) =>
          `<div class="service"><div><strong>${n}</strong><small>${d}</small></div>${pill(["active", "running"].includes(services[k]) ? "active" : "unknown", services[k] || "Нет данных")}</div>`,
      )
      .join(
        "",
      )}<div class="service"><div><strong>R-TrustTunnel</strong><small>Клиенты и подписанные обновления</small></div>${pill("running", "seq " + (state.updates?.active_sequence ?? "—"))}</div></div><div class="card"><h2>Каналы доставки</h2><div class="service"><div><strong>Telegram</strong><small>Существующий приватный бот</small></div>${pill(state.telegram?.running ? "active" : "unknown", state.telegram?.running ? "Работает" : "Нет связи")}</div><div class="service"><div><strong>E-mail</strong><small>SMTP из настроек TrustTunnel</small></div>${pill(state.smtp ? "active" : "unknown", state.smtp ? "Настроен" : "Не настроен")}</div></div></div></div><div class="heading"><h2>Последние операции</h2></div>${jobsTable((state.jobs || []).slice(0, 5))}`
  );
}
function users() {
  const h = Array.isArray(state.hysteria_users) ? state.hysteria_users : [];
  return (
    heading(
      "Пользователи",
      "Учётные записи обоих VPN. Идентичности разных протоколов показаны отдельно.",
      btn("+ Добавить", "new-user", "", "primary"),
    ) +
    `<div class="toolbar"><input id="user-search" placeholder="Поиск по имени или e-mail" aria-label="Поиск пользователей"><select id="user-filter" aria-label="Протокол"><option value="">Все протоколы</option><option>TrustTunnel</option><option>Hysteria</option></select></div>` +
    table(
      ["Пользователь", "Протокол", "Доступ", "Использование", "Управление"],
      [
        ...(state.users || []).map(
          (u) =>
            `<tr data-search="${esc(u.email.toLowerCase())}" data-protocol="TrustTunnel"><td>${esc(u.email)}<small>#${u.id}</small></td><td>${pill("running", "TrustTunnel")}</td><td>${pill(u.status)}</td><td>—</td><td>${btn("Ключ", "user-key", `data-id="${u.id}"`)}${btn("Пароль", "password", `data-id="${u.id}"`)}${btn("Контакт", "contact", `data-source="trusttunnel" data-id="${u.id}"`)}${btn(u.status === "blocked" ? "Включить" : "Блокировать", "status", `data-source="trusttunnel" data-id="${u.id}" data-block="${u.status !== "blocked"}"`)}</td></tr>`,
        ),
        ...h.map(
          (u) =>
            `<tr data-search="${esc(u.username.toLowerCase())}" data-protocol="Hysteria"><td>${esc(u.username)}<small>#${u.id}</small></td><td>${pill("running", "Hysteria")}</td><td>${pill(u.deleted ? "blocked" : "active")}</td><td>${bytes(u.download + u.upload)}<small>До ${new Date(u.expire_time).toLocaleDateString("ru")}</small></td><td>${btn("Ключ", "export", `data-source="hysteria" data-id="${u.id}"`)}${btn("Сменить ключ", "rotate", `data-source="hysteria" data-id="${u.id}"`)}${btn("Лимиты", "hysteria-limits", `data-id="${u.id}"`)}${btn("Контакт", "contact", `data-source="hysteria" data-id="${u.id}"`)}${btn(u.deleted ? "Включить" : "Блокировать", "status", `data-source="hysteria" data-id="${u.id}" data-block="${!u.deleted}"`)}</td></tr>`,
        ),
      ],
    ) +
    (state.hysteria_users?.error
      ? '<p class="note">Hysteria временно недоступна.</p>'
      : "")
  );
}
function keys() {
  return (
    heading(
      "Ключи и устройства",
      "Секреты раскрываются только по отдельному запросу. Отзыв VPN-ключа прекращает доступ.",
    ) +
    table(
      ["Владелец / ключ", "Протокол", "Статус", "Действия"],
      (state.keys || []).map(
        (k) =>
          `<tr><td>${esc(k.email)}<small>${esc(k.tt_username)} · ${esc(k.label)}</small></td><td>TrustTunnel</td><td>${pill(k.revoked_at ? "blocked" : "active", k.revoked_at ? "Отозван" : "Действует")}</td><td>${!k.revoked_at ? btn("Показать / скачать", "export", `data-source="trusttunnel" data-id="${k.id}"`) + btn("Ротация", "rotate", `data-source="trusttunnel" data-id="${k.id}"`) + btn("Отозвать", "revoke", `data-id="${k.id}"`, "danger") : ""}</td></tr>`,
      ),
    ) +
    `<div class="note">Ключи Hysteria доступны в разделе «Пользователи». API-регистрация устройства и VPN-ключ имеют отдельные сроки и отзыв.</div><h2>Регистрации R-TrustTunnel</h2>` +
    table(
      ["Устройство", "Владелец", "Платформа", "Последняя активность", "Статус"],
      (state.devices || []).map(
        (d) =>
          `<tr><td>${esc(d.name)}</td><td>#${d.user_id}</td><td>${esc(d.platform)}</td><td>${esc(d.last_seen_at || "—")}</td><td>${pill(d.revoked_at ? "blocked" : "active")}${!d.revoked_at ? btn("Отозвать", "device-revoke", `data-id="${d.id}"`) : ""}</td></tr>`,
      ),
    )
  );
}
function routeRow(target = "local", kind = "suffix", value = "") {
  return `<div class="route-row"><select aria-label="Выход">${["local", "primary", "reserve", "reject"].map((t) => `<option value="${t}" ${t === target ? "selected" : ""}>${{ local: "Напрямую", primary: "Основной", reserve: "Резервный", reject: "Блокировать" }[t]}</option>`).join("")}</select><select aria-label="Тип правила">${["suffix", "geoip", "cidr"].map((k) => `<option ${k === kind ? "selected" : ""}>${k}</option>`).join("")}</select><input aria-label="Домен или сеть" value="${esc(value)}" placeholder="example.com"><button data-action="remove-rule" aria-label="Удалить правило">×</button></div>`;
}
function routing() {
  const r = state.routing;
  if (!r || r.error)
    return (
      heading("Маршрутизация", "Управление выходами") +
      '<div class="empty">Агент маршрутизации недоступен</div>'
    );
  const names = Object.fromEntries(r.exits.map((e) => [e.name, e.id]));
  const rules = r.rules
    .slice(3, -1)
    .map((v) => {
      const m = v.match(/^([a-zA-Z0-9_-]+)\((suffix:|geoip:)?([^()]+)\)$/);
      return m
        ? routeRow(names[m[1]] || m[1], m[2]?.slice(0, -1) || "cidr", m[3])
        : `<p class="error">Неподдерживаемое правило: ${esc(v)}</p>`;
    })
    .join("");
  return (
    heading(
      "Маршрутизация",
      "Приоритет сверху вниз. Сначала исключения, затем общий выход.",
      btn("Проверить оба выхода", "check-routes"),
    ) +
    `<div class="grid"><div class="card"><h2>Hysteria · общий выход</h2><label class="field">Весь трафик, не попавший под исключения<select id="route-exit">${r.exits.map((e) => `<option value="${esc(e.id)}" ${e.id === r.selected ? "selected" : ""}>${esc(e.id)} · ${esc(e.host)}</option>`).join("")}</select></label><h2>Исключения</h2><div id="route-rules">${rules}</div>${btn("+ Правило", "add-rule")}<div class="actions">${btn("Проверить изменения", "preview-routes", "", "primary")}</div></div><div class="stack"><div class="card"><h2>Область действия</h2><div class="service"><strong>Hysteria 2</strong>${pill("active", r.selected)}</div><div class="service"><strong>TrustTunnel</strong>${pill("running", "Напрямую")}</div><div class="service"><strong>Трафик сервера</strong>${pill("running", "Напрямую")}</div><div class="note">Правила Hysteria не меняют egress TrustTunnel или системную таблицу маршрутов.</div></div><div class="card"><h2>Защита применения</h2><p class="subtitle">Перед применением проверяется выход. После — реальный запрос через Hysteria. При сбое восстанавливается предыдущая конфигурация.</p><p class="subtitle">Доступ к панелям и блокировка приватных сетей сохраняются. Переключение кратко переподключит клиентов.</p><details><summary>Текущие правила</summary><pre>${esc(r.rules.join("\n"))}</pre></details></div></div></div>`
  );
}
function updates() {
  const u = state.updates || {};
  return (
    heading(
      "Обновления",
      "Подписанные клиентские релизы и подготовленные пакеты серверов.",
    ) +
    `<div class="note">Публикация канала не устанавливает обновление на устройства. Клиент проверяет подпись, срок, хеш и защиту от понижения версии.</div><h2>R-TrustTunnel · Windows</h2>` +
    table(
      ["Релиз", "Цель", "Проверка", "Канал", "Действие"],
      (u.releases || []).map(
        (r) =>
          `<tr><td>${esc(r.version || r.id)}<small>sequence ${esc(r.sequence || r.id)}</small></td><td>${esc(r.target || "windows-x86_64")}</td><td>${pill(r.valid ? "active" : "unknown", r.valid ? "Подпись и срок ОК" : "Недействителен")}</td><td>${r.active ? pill("active", "Текущий") : "Архив / кандидат"}</td><td>${r.valid && !r.active && r.sequence >= (u.active_sequence || 0) ? btn("Опубликовать", "promote", `data-sequence="${r.sequence}"`) : "—"}</td></tr>`,
      ),
    ) +
    `<div class="note">Полный хеш установщика проверяется перед публикацией. Истёкшие манифесты не публикуются повторно.</div><h2>Серверные пакеты</h2>` +
    table(
      ["Компонент", "Версия", "Действие"],
      (u.server_packages || []).map(
        (p) =>
          `<tr><td>${esc(p.component)}</td><td>${esc(p.version)}</td><td>${btn("Установить", "server-update", `data-package="${esc(p.id)}"`)}</td></tr>`,
      ),
    ) +
    `<p class="note">Пакеты предварительно готовятся оператором на сервере. Произвольные файлы и команды из браузера не исполняются. Linux-клиенты получают обновления через существующий Flatpak-репозиторий.</p><a href="/rtrust/releases/linux-candidate/R-TrustTunnel.flatpakref">Скачать Flatpakref ↗</a>`
  );
}
function campaigns() {
  return (
    heading(
      "Рассылки",
      "Черновик → проверка получателей → подтверждённая отправка.",
      btn("+ Новая рассылка", "new-campaign", "", "primary"),
    ) +
    table(
      ["Тема", "Канал", "Статус", "Создана", "Действие"],
      (state.campaigns || []).map(
        (c) =>
          `<tr><td>${esc(c.subject)}</td><td>${esc(c.channel)}</td><td>${pill(c.state)}</td><td>${esc(c.created)}</td><td>${btn("Открыть", "campaign-detail", `data-id="${c.id}"`)}</td></tr>`,
      ),
    ) +
    `<div class="note">Получатели добавляются через «Контакт» в разделе пользователей с явным согласием. Доставка каждого адресата фиксируется отдельно; после неоднозначного сбоя автоматического повтора нет.</div>`
  );
}
function telegram() {
  const t = state.telegram || {};
  return (
    heading("Telegram", "Интеграция с существующим приватным ботом.") +
    `<div class="grid"><div class="card"><h2>Бот управления</h2><div class="service"><strong>Сервис</strong>${pill(t.running ? "active" : "unknown", t.running ? "Работает" : "Нет данных")}</div><div class="service"><strong>Токен</strong>${pill(t.configured ? "active" : "unknown", t.configured ? "На сервере" : "Не настроен")}</div><div class="service"><strong>Владелец</strong><code>${esc(t.owner || "—")}</code></div><div class="note">Токен не передаётся в браузер. Управляющие команды бота доступны только владельцу в личном чате.</div></div><div class="card"><h2>Доставка пользователям</h2><p class="subtitle">Укажите Telegram user ID в контакте пользователя и зафиксируйте согласие. Получатель должен сначала открыть существующего бота и нажать Start.</p><p class="subtitle">Для отправки создайте рассылку в канале Telegram, проверьте адресатов и подтвердите.</p>${btn("Открыть рассылки →", "navigate", 'data-target="campaigns"')}</div></div><h2>Контакты Telegram</h2>` +
    table(
      ["Учётная запись", "Telegram ID", "Согласие"],
      (state.contacts || [])
        .filter((c) => c.chat_id)
        .map(
          (c) =>
            `<tr><td>${esc(c.source)} #${c.user_id}</td><td>${c.chat_id}</td><td>${pill(c.consent ? "active" : "blocked", c.consent ? "Получено" : "Нет")}</td></tr>`,
        ),
    )
  );
}
function jobsTable(jobs) {
  return table(
    ["Операция", "Статус", "Результат", "Время"],
    jobs.map((j) => {
      let r = {};
      try {
        r = JSON.parse(j.result || "{}");
      } catch {}
      return `<tr><td><code>${esc(j.action)}</code></td><td>${pill(j.state)}</td><td class="wrap">${esc(r.message || "—")}</td><td>${esc(j.updated)}</td></tr>`;
    }),
  );
}
function journal() {
  return (
    heading(
      "Журнал операций",
      "Результаты применения и действия администраторов.",
    ) +
    jobsTable(state.jobs || []) +
    `<div class="note">Не подтверждено — операция была прервана. Сначала проверьте фактическое состояние; повтор может создать дубликат.</div>` +
    table(
      ["Администратор", "Действие", "Результат", "Время"],
      (state.audit || []).map(
        (a) =>
          `<tr><td>#${a.actor}</td><td><code>${esc(a.action)}</code></td><td>${esc(a.detail)}</td><td>${esc(a.at)}</td></tr>`,
      ),
    )
  );
}
function render() {
  const map = {
    overview,
    users,
    keys,
    routing,
    updates,
    campaigns,
    telegram,
    audit: journal,
  };
  $("#content").innerHTML = map[page]();
  $("#breadcrumb").textContent = titles[page];
  document
    .querySelectorAll("nav button")
    .forEach((b) => b.classList.toggle("selected", b.dataset.page === page));
  if (page === "users") {
    const filter = () =>
      document
        .querySelectorAll("tr[data-search]")
        .forEach(
          (r) =>
            (r.hidden =
              !r.dataset.search.includes(
                $("#user-search").value.toLowerCase(),
              ) ||
              (!!$("#user-filter").value &&
                r.dataset.protocol !== $("#user-filter").value)),
        );
    $("#user-search").oninput = filter;
    $("#user-filter").onchange = filter;
  }
  if (page === "routing") {
    $("#content").oninput = () => (routeDirty = true);
  } else {
    $("#content").oninput = null;
    routeDirty = false;
  }
}
function navigate(target) {
  page = target;
  routeDirty = false;
  render();
}
function formSubmit(id, callback) {
  $("#" + id).onsubmit = async (e) => {
    e.preventDefault();
    const b = e.target.querySelector("[type=submit]");
    if (b) b.disabled = true;
    try {
      await callback(new FormData(e.target));
    } catch (err) {
      notice(err.message, true);
    } finally {
      if (b) b.disabled = false;
    }
  };
}
async function handle(b) {
  const a = b.dataset.action,
    id = Number(b.dataset.id),
    source = b.dataset.source;
  if (a === "navigate") return navigate(b.dataset.target);
  if (a === "new-user") {
    modal(
      "Добавить пользователя",
      `<form id="user-form"><label class="field">Протокол<select name="source"><option value="trusttunnel">TrustTunnel / R-TrustTunnel</option><option value="hysteria">Hysteria</option></select></label><label class="field">E-mail для TrustTunnel / логин для Hysteria<input name="name" required maxlength="200"></label><div class="note">TrustTunnel: после создания задайте пароль и выпустите ключ. Hysteria: автоматически создаётся ключ на 365 дней, до 3 устройств.</div><button type="submit" class="primary">Создать</button></form>`,
    );
    formSubmit("user-form", (f) =>
      job(
        f.get("source") + ".create",
        f.get("source") === "hysteria"
          ? { username: f.get("name"), days: 365, devices: 3 }
          : { email: f.get("name") },
      ),
    );
  }
  if (a === "status")
    confirmJob(
      "Изменить доступ",
      b.dataset.block === "true"
        ? "Заблокировать пользователя и отключить его VPN-доступ?"
        : "Восстановить доступ пользователя?",
      source + (b.dataset.block === "true" ? ".block" : ".unblock"),
      { id },
    );
  if (a === "user-key")
    confirmJob(
      "Новый ключ TrustTunnel",
      "Выпустить ключ? Endpoint кратко перезапустится для применения.",
      "trusttunnel.key",
      { id },
    );
  if (a === "rotate")
    confirmJob(
      "Ротация ключа",
      "Старый ключ перестанет работать. Потребуется передать новый профиль пользователю. Клиенты могут переподключиться.",
      source + ".rotate",
      { id },
    );
  if (a === "revoke")
    confirmJob(
      "Отозвать ключ",
      "VPN-доступ по этому ключу будет прекращён. Endpoint кратко перезапустится.",
      "trusttunnel.revoke",
      { id },
    );
  if (a === "device-revoke")
    confirmJob(
      "Отозвать устройство",
      "Будут отозваны API-регистрация и привязанные VPN-ключи устройства.",
      "trusttunnel.device-revoke",
      { id },
    );
  if (a === "hysteria-limits") {
    const u = state.hysteria_users.find((u) => u.id === id);
    modal(
      "Срок и лимиты Hysteria",
      `<form id="limits-form"><label class="field">Продлить от сегодня, дней<input type="number" name="days" min="1" max="3650" value="365" required></label><label class="field">Одновременные устройства<input type="number" name="devices" min="1" max="100" value="${u.device_no || 3}" required></label><label class="field">Общая квота GB (-1 = без лимита)<input type="number" name="quota" min="-1" max="100000" value="${u.quota < 0 ? -1 : Math.ceil(u.quota / 1073741824)}" required></label><button type="submit" class="primary">Применить</button></form>`,
    );
    formSubmit("limits-form", (f) =>
      job("hysteria.update", {
        id,
        days: Number(f.get("days")),
        devices: Number(f.get("devices")),
        quota_gb: Number(f.get("quota")),
      }),
    );
  }
  if (a === "password") {
    modal(
      "Пароль пользователя",
      `<form id="password-form"><label class="field">Новый пароль<input type="password" name="password" minlength="12" maxlength="128" required autocomplete="new-password"></label><button type="submit" class="primary">Сохранить</button></form>`,
    );
    formSubmit("password-form", async (f) => {
      await api("password", { id, password: f.get("password") });
      $("#modal").close();
      notice("Пароль изменён");
    });
  }
  if (a === "export") {
    modal(
      "Раскрытие VPN-ключа",
      `<p>Ссылка содержит секрет подключения. Передавайте её только владельцу.</p><button id="reveal" class="primary">Показать ключ</button>`,
    );
    $("#reveal").onclick = async () => {
      try {
        const r = await api("export", { source, id, consent: true });
        $("#modal-body").innerHTML =
          `<pre id="secret"></pre><button id="download" class="primary">Скачать</button>`;
        $("#secret").textContent = r.content;
        $("#download").onclick = () => {
          const url = URL.createObjectURL(
            new Blob([r.content], { type: "text/plain" }),
          );
          const link = document.createElement("a");
          link.href = url;
          link.download = source + "-" + id + ".txt";
          link.click();
          setTimeout(() => URL.revokeObjectURL(url), 5000);
        };
      } catch (e) {
        notice(e.message, true);
        $("#modal").close();
      }
    };
  }
  if (a === "contact") {
    const c =
      (state.contacts || []).find(
        (c) => c.source === source && c.user_id === id,
      ) || {};
    modal(
      "Контакт пользователя",
      `<form id="contact-form"><label class="field">E-mail<input type="email" name="email" value="${esc(c.email)}"></label><label class="field">Telegram user ID<input name="chat" inputmode="numeric" value="${esc(c.chat_id)}"></label><label><input type="checkbox" name="consent" ${c.consent ? "checked" : ""}> Получено согласие на уведомления</label><div class="actions"><button type="submit" class="primary">Сохранить</button></div></form>`,
    );
    formSubmit("contact-form", async (f) => {
      await api("contacts", {
        source,
        id,
        email: f.get("email"),
        chat_id: f.get("chat") ? Number(f.get("chat")) : null,
        consent: f.get("consent") === "on",
      });
      $("#modal").close();
      notice("Контакт сохранён");
      await refresh();
    });
  }
  if (a === "add-rule") {
    $("#route-rules").insertAdjacentHTML("beforeend", routeRow());
    routeDirty = true;
  }
  if (a === "remove-rule") {
    b.closest(".route-row").remove();
    routeDirty = true;
  }
  if (a === "check-routes") await job("routes.check", {});
  if (a === "preview-routes") {
    if ($("#route-rules .error"))
      throw Error("Есть неподдерживаемые правила. Применение запрещено.");
    const rules = [...document.querySelectorAll(".route-row")].map((r) => ({
      target: r.children[0].value,
      kind: r.children[1].value,
      value: r.children[2].value,
    }));
    const data = {
      exit: $("#route-exit").value,
      rules,
      revision: state.routing.revision,
    };
    confirmJob(
      "Применить маршруты",
      `Выход: ${data.exit}. Исключений: ${rules.length}. Защищённые правила сохраняются. Hysteria кратко перезапустится; при ошибке проверки сработает откат.`,
      "routes.apply",
      data,
    );
    routeDirty = false;
  }
  if (a === "promote")
    confirmJob(
      "Опубликовать обновление",
      "Переключить канал Windows на sequence " + b.dataset.sequence + "?",
      "updates.promote",
      { sequence: Number(b.dataset.sequence) },
    );
  if (a === "server-update")
    confirmJob(
      "Обновить серверный компонент",
      "Установить подготовленный пакет? Возможен краткий перерыв VPN.",
      "updates.server",
      { package: b.dataset.package },
    );
  if (a === "new-campaign") {
    modal(
      "Новая рассылка",
      `<form id="campaign-form"><label class="field">Канал<select name="channel"><option value="email">E-mail</option><option value="telegram">Telegram</option></select></label><label class="field">Тема<input name="subject" required maxlength="160"></label><label class="field">Текст<textarea name="body" maxlength="3300" required></textarea></label><h3>Получатели с согласием</h3><div class="contact-list">${
        (state.contacts || [])
          .filter((c) => c.consent)
          .map(
            (c) =>
              `<label><input type="checkbox" name="recipient" value="${esc(c.source)}:${c.user_id}">${esc(c.source)} #${c.user_id} · ${esc(c.email || c.chat_id)}</label>`,
          )
          .join("") || '<p class="muted">Добавьте контакты пользователей.</p>'
      }</div><button type="submit" class="primary">Сохранить черновик</button></form>`,
    );
    formSubmit("campaign-form", async (f) => {
      const r = await api("campaigns", {
        channel: f.get("channel"),
        subject: f.get("subject"),
        body: f.get("body"),
        recipients: f.getAll("recipient").map((v) => {
          const [source, id] = v.split(":");
          return { source, id: Number(id) };
        }),
      });
      $("#modal").close();
      notice("Черновик сохранён. Сообщения не отправлены.");
      await refresh();
      await showCampaign(r.id);
    });
  }
  if (a === "campaign-detail") await showCampaign(b.dataset.id);
}
async function showCampaign(id) {
  const c = await api("campaigns/" + id);
  modal(
    "Рассылка · " + c.subject,
    `<p>${pill(c.state)} · ${esc(c.channel)}</p><pre>${esc(c.body)}</pre>${table(
      ["Получатель", "Статус"],
      c.deliveries.map(
        (d) =>
          `<tr><td>${esc(d.recipient)}</td><td>${pill(d.state)}<small>${esc(d.error || "")}</small></td></tr>`,
      ),
    )}${c.state === "draft" ? '<div class="actions"><button id="send-campaign" class="primary">Подтвердить отправку всем указанным получателям</button></div>' : ""}`,
  );
  if ($("#send-campaign"))
    $("#send-campaign").onclick = async () => {
      try {
        $("#send-campaign").disabled = true;
        await job("campaign.send", { id });
      } catch (e) {
        notice(e.message, true);
        $("#modal").close();
      }
    };
}
document.addEventListener("click", (e) => {
  const nav = e.target.closest("[data-page]");
  if (nav) navigate(nav.dataset.page);
  const b = e.target.closest("[data-action]");
  if (b) handle(b).catch((e) => notice(e.message, true));
});
$("#refresh").onclick = () => {
  if (routeDirty) {
    notice(
      "Сначала примените изменения маршрутов или перейдите в другой раздел.",
    );
    return;
  }
  refresh();
};
$("#modal").addEventListener("close", () => {
  $("#modal-body").replaceChildren();
});
refresh();
