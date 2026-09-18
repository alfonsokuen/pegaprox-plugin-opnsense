/* Native administration workspace. No persistent drafts, secrets or API cache. */
(() => {
  "use strict";
  const $ = selector => document.querySelector(selector);
  const theme = new URLSearchParams(location.search).get("theme") || "corp-dark";
  if (/^cloud/i.test(theme)) document.documentElement.classList.add("theme-cloud");
  else if (/light/i.test(theme)) document.documentElement.classList.add("theme-light");
  $("#back-panel").href = `./ui?theme=${encodeURIComponent(theme)}`;
  const state = { resources: [], operations: [], catalogReadOnly: true, resource: null, rows: [], total: 0,
    page: 1, rowCount: 50, query: "", readOnly: true, loaded: false, listing: false,
    editing: false, fields: [], values: {}, uuid: "", revision: "", dirty: false,
    writing: false, loadingDetail: false, reconcile: false, epoch: 0, listTicket: 0 };
  const backups = { available: false, items: [], busy: false, loaded: false, uncertain: false };
  const node = (tag, text, attributes = {}) => {
    const element = document.createElement(tag);
    if (text !== null && text !== undefined) element.textContent = String(text);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
    return element;
  };
  function notice(selector, text) {
    const element = $(selector);
    element.textContent = text || "";
    element.hidden = !text;
  }
  function failureText(error) {
    const names = { 401: "Autenticación rechazada", 403: "Sin permiso para esta operación",
      404: "Módulo o API no disponible", 409: "El estado cambió: revisa la configuración",
      422: "Revisa los valores del formulario", 502: "El firewall no confirmó la operación",
      504: "El firewall no respondió a tiempo" };
    const title = error.error === "unsupported" ? "Módulo no disponible en este firewall"
      : names[error.status] || "No se pudo completar la operación";
    return `${title}${error.detail ? `. ${error.detail}` : ""}`;
  }
  async function api(route, parameters = {}, body) {
    const url = new URL(`./${route}`, location.href);
    for (const [key, value] of Object.entries(parameters)) url.searchParams.set(key, value);
    let response, result;
    try {
      response = await fetch(url, { method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store",
        headers: body ? { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" } : {},
        ...(body ? { body: JSON.stringify(body) } : {}) });
      result = await response.json();
    } catch {
      throw { status: response?.status || 0, error: "transport", partial: !!body,
        detail: "No se recibió una respuesta válida. Comprueba la conexión y el estado del firewall." };
    }
    if (!response.ok || result.ok !== true) throw { ...result, status: response.status };
    if (!result.data || typeof result.data !== "object") throw { status: 502, partial: !!body,
      error: "malformed", detail: "La respuesta no contiene los datos esperados." };
    return result.data;
  }
  const locked = () => state.writing || state.loadingDetail || backups.busy;
  const writable = () => state.loaded && (state.resource?.operation && state.resource.method === "GET" || !state.readOnly && !state.catalogReadOnly) && !locked() && !state.reconcile;
  const supports = action => Array.isArray(state.resource?.operations)
    ? state.resource.operations.includes(action)
    : !!state.resource?.[{ create: "add", update: "set", delete: "delete" }[action]];
  function controls() {
    if (state.resource?.backup) {
      $("#access-mode").textContent = backups.available ? "Copias locales · administrador" : "Acceso restringido";
      $("#new-item").hidden = true; $("#refresh-list").hidden = false;
      $("#refresh-list").disabled = backups.busy;
      $("#backup-create").disabled = !backups.available || !backups.loaded || backups.busy || backups.uncertain;
      $("#backup-reconcile").hidden = !backups.uncertain;
      $("#backup-reconcile").disabled = backups.busy;
      document.querySelectorAll(".backup-action,.module-link").forEach(button => { button.disabled = backups.busy; });
      notice("#resource-access", "Acceso exclusivo de administrador. Las copias locales no modifican el firewall.");
      return;
    }
    $("#access-mode").textContent = state.catalogReadOnly ? "Solo lectura" : state.resource
      ? !state.loaded ? "Acceso por comprobar" : state.readOnly ? "Solo lectura" : "Administración disponible"
      : "Acceso por comprobar en cada módulo";
    $("#new-item").hidden = state.resource?.singleton === true || !supports("create");
    $("#new-item").disabled = !writable() || !supports("create") || state.listing;
    $("#refresh-list").disabled = locked() || state.listing;
    $("#entry-fields").disabled = !writable();
    $("#save-item").disabled = !writable() || !state.editing || !supports(state.uuid ? "update" : "create");
    $("#delete-item").disabled = !writable() || !state.uuid || !state.revision || !supports("delete");
    $("#cancel-edit").disabled = locked() || state.reconcile;
    $("#cancel-edit").textContent = state.resource?.operation ? "Restablecer formulario" : "Cerrar detalle";
    $("#reconcile").hidden = !state.reconcile;
    $("#reconcile").disabled = locked() || state.listing;
    $("#save-item").textContent = state.writing ? "Aplicando y verificando…" : state.uuid ? "Guardar cambios" : "Crear entrada";
    if (state.resource?.operation) {
      $("#new-item").hidden = true; $("#refresh-list").hidden = true;
      $("#save-item").disabled = !writable() || !state.editing;
      $("#save-item").textContent = state.writing ? "Consultando resultado…" : state.resource.method === "GET" ? "Consultar" : "Ejecutar operación";
    } else $("#refresh-list").hidden = false;
    $("#prev-page").disabled = locked() || state.listing || !state.loaded || state.page <= 1;
    $("#next-page").disabled = locked() || state.listing || !state.loaded || state.page * state.rowCount >= state.total;
    $("#list-search-form button").disabled = locked() || state.listing;
    $("#entry-form").setAttribute("aria-busy", String(state.writing || state.loadingDetail));
    $("#draft-status").textContent = state.dirty ? "Cambios sin guardar" : "";
    document.querySelectorAll(".module-link").forEach(button => { button.disabled = locked(); });
    document.querySelectorAll(".detail-button").forEach(button => { button.disabled = locked() || state.reconcile; });
    notice("#resource-access", !state.loaded ? "Las escrituras estarán disponibles después de comprobar el acceso al módulo."
      : state.readOnly || state.catalogReadOnly ? "Modo de solo lectura. Puedes consultar las entradas y su detalle."
      : state.resource?.operation ? ""
      : !supports("create") && !supports("update") ? "Este módulo permite consultar su configuración." : "");
  }
  function allowDiscard() {
    if (locked()) return false;
    if (state.reconcile) { $("#editor").scrollIntoView({ block: "nearest" }); $("#reconcile").focus(); return false; }
    return !state.dirty || confirm("¿Descartar los cambios sin guardar de este formulario?");
  }
  function closeEditor() {
    state.editing = false; state.values = {}; state.fields = []; state.uuid = "";
    state.revision = ""; state.dirty = false;
    $("#entry-fields").replaceChildren(); $("#editor").hidden = true;
    notice("#editor-error", ""); notice("#reconcile-warning", ""); controls();
  }
  function renderNavigation() {
    const query = $("#module-search").value.trim().toLocaleLowerCase();
    const all = navigationItems();
    const visible = all.filter(resource => `${resource.label} ${resource.group} ${resource.id}`.toLocaleLowerCase().includes(query));
    const groups = new Map();
    for (const resource of visible) {
      const group = resource.group || "Configuración";
      if (!groups.has(group)) groups.set(group, []);
      groups.get(group).push(resource);
    }
    const fragments = [];
    for (const [name, resources] of groups) {
      const section = node("section", null, { class: "nav-group" });
      section.append(node("h2", name));
      for (const resource of resources) {
        const button = node("button", null, { type: "button", class: "module-link", "data-resource": resource.id });
        button.append(node("span", resource.label || resource.id));
        if (state.resource?.id === resource.id) button.setAttribute("aria-current", "page");
        button.addEventListener("click", () => selectResource(resource));
        section.append(button);
      }
      fragments.push(section);
    }
    if (!visible.length) fragments.push(node("p", "No se encontraron módulos.", { class: "muted" }));
    $("#module-nav").replaceChildren(...fragments);
    $("#module-count").textContent = `${visible.length} de ${all.length} módulos y operaciones`;
    controls();
  }
  function navigationItems() {
    return [...state.resources, ...state.operations, ...(backups.available
      ? [{ id: "backups", label: "Copias de seguridad", group: "Sistema", backup: true }] : [])];
  }
  function columns() {
    return (state.resource?.columns || []).map(column => typeof column === "string"
      ? { name: column, label: state.resource.fields?.find(field => field.name === column)?.label || column }
      : { name: column.name || column.key, label: column.label || column.name || column.key })
      .filter(column => column.name && !state.resource.fields?.some(field => field.name === column.name && (field.secret || field.kind === "password")));
  }
  function renderTable() {
    const cols = columns();
    const heading = node("tr");
    for (const col of cols) heading.append(node("th", col.label, { scope: "col" }));
    heading.append(node("th", "Detalle", { scope: "col" }));
    $("#table-head").replaceChildren(heading);
    const rows = [];
    for (const row of state.rows) {
      const tr = node("tr");
      for (const col of cols) {
        const value = row[col.name];
        tr.append(node("td", value === null || value === undefined ? "—" : Array.isArray(value) ? value.join(", ")
          : typeof value === "boolean" ? value ? "Sí" : "No" : typeof value === "object" ? "—" : value));
      }
      const cell = node("td");
      const button = node("button", "Ver detalle", { type: "button", class: "detail-button" });
      button.disabled = !row.uuid;
      button.addEventListener("click", () => openEditor(row.uuid));
      if (row.uuid) cell.append(button); else cell.append(node("span", "Sin identificador", { class: "muted" }));
      tr.append(cell); rows.push(tr);
    }
    if (!rows.length) {
      const row = node("tr");
      row.append(node("td", state.listing ? "Consultando el firewall…" : state.loaded ? "No hay entradas que coincidan con esta consulta." : "La lista no está disponible.", { class: "empty", colspan: cols.length + 1 }));
      rows.push(row);
    }
    $("#table-body").replaceChildren(...rows);
    $("#list-count").textContent = state.loaded ? `${state.total} entradas · ${state.rows.length} en esta página` : "Sin datos confirmados";
    $("#page-number").textContent = String(state.page);
    controls();
  }
  async function loadList(page = state.page) {
    if (!state.resource || locked()) return;
    const epoch = state.epoch, ticket = ++state.listTicket;
    state.listing = true; state.page = page; controls();
    $("#table-region").setAttribute("aria-busy", "true");
    notice("#list-error", "");
    try {
      const data = await api("manage", { resource: state.resource.id, page, row_count: state.rowCount, search: state.query });
      if (epoch !== state.epoch || ticket !== state.listTicket) return;
      if (!Array.isArray(data.rows) || !Number.isFinite(Number(data.total))) throw { status: 502, detail: "Lista incompleta o inválida." };
      state.rows = data.rows; state.total = Number(data.total); state.loaded = true;
      state.readOnly = data.read_only !== false;
    } catch (error) {
      if (epoch !== state.epoch || ticket !== state.listTicket) return;
      state.rows = []; state.total = 0; state.loaded = false; state.readOnly = true;
      notice("#list-error", failureText(error));
    } finally {
      if (epoch === state.epoch && ticket === state.listTicket) {
        state.listing = false; $("#table-region").setAttribute("aria-busy", "false"); renderTable();
      }
    }
  }
  async function selectResource(resource) {
    if (resource.id === state.resource?.id || !allowDiscard()) return;
    ++state.epoch; state.resource = resource; state.rows = []; state.total = 0;
    state.page = 1; state.query = ""; state.loaded = false; state.readOnly = true;
    closeEditor(); notice("#result-status", ""); notice("#list-error", "");
    $("#welcome").hidden = true; $("#resource-view").hidden = false;
    $("#resource-title").textContent = resource.label || resource.id;
    $("#resource-group").textContent = resource.group || "Configuración";
    $("#resource-description").textContent = resource.description || "Consulta las entradas y abre su detalle para revisar la configuración.";
    $("#list-search").value = "";
    $(".list-panel").hidden = !!resource.operation || !!resource.backup;
    $("#backups-panel").hidden = !resource.backup;
    $("#operation-output").hidden = true;
    history.replaceState(null, "", `${location.pathname}${location.search}#${encodeURIComponent(resource.id)}`);
    renderNavigation();
    if (resource.backup) await loadBackups();
    else if (resource.operation) {
      openOperation();
      if (resource.method === "GET" && !state.fields.some(field => field.required && !state.values[field.name])) await operate();
    } else { renderTable(); await loadList(1); }
  }
  async function loadBackups() {
    if (backups.busy || !backups.available) return;
    backups.busy = true; controls(); notice("#backup-error", "");
    try {
      const data = await api("backups");
      if (!Array.isArray(data.items)) throw { status: 502, detail: "La lista de copias no es válida." };
      backups.items = data.items; backups.loaded = true; renderBackups();
    } catch (error) { backups.loaded = false; notice("#backup-error", failureText(error)); }
    finally { backups.busy = false; controls(); }
  }
  function renderBackups() {
    const rows = [];
    for (const item of backups.items) {
      const row = node("tr");
      const date = new Date(item.date);
      row.append(node("td", Number.isNaN(date.getTime()) ? item.date || "—" : date.toLocaleString()), node("td", item.host || "—"),
        node("td", Number.isFinite(Number(item.size)) ? `${Number(item.size).toLocaleString()} B` : "—"), node("td", item.sha256 || "—", { class: "backup-digest" }));
      const cell = node("td");
      const download = node("button", "Descargar XML", { type: "button", class: "backup-action" });
      download.addEventListener("click", () => downloadBackup(item.id));
      const remove = node("button", "Eliminar copia", { type: "button", class: "backup-action danger-button" });
      remove.addEventListener("click", () => mutateBackup("delete", item.id));
      cell.append(download, document.createTextNode(" "), remove); row.append(cell); rows.push(row);
    }
    if (!rows.length) { const row = node("tr"); row.append(node("td", "Todavía no hay copias locales guardadas.", { colspan: 5, class: "empty" })); rows.push(row); }
    $("#backup-rows").replaceChildren(...rows);
  }
  async function mutateBackup(action, id) {
    if (!backups.available || !backups.loaded || backups.busy || backups.uncertain) return;
    if (action === "delete" && !confirm("¿Eliminar esta copia local? Esta acción no modifica la configuración del firewall.")) return;
    backups.busy = true; controls(); notice("#backup-error", ""); notice("#backup-status", "");
    try {
      await api("backups", {}, { action, ...(id ? { id } : {}) });
      notice("#backup-status", action === "create" ? "Copia del último histórico guardada y cifrada." : "Copia local eliminada.");
      backups.busy = false; await loadBackups();
    } catch (error) {
      notice("#backup-error", failureText(error));
      if (error.partial === true || ![400, 401, 403, 404, 409, 422].includes(error.status)) {
        backups.uncertain = true; notice("#backup-status", "No se confirmó el resultado. Actualiza y revisa la lista antes de repetir la operación.");
      }
    } finally { backups.busy = false; controls(); }
  }
  async function downloadBackup(id) {
    if (backups.busy || !backups.available) return;
    backups.busy = true; controls(); notice("#backup-error", "");
    let objectUrl;
    try {
      const response = await fetch(new URL(`./backups?id=${encodeURIComponent(id)}&download=1`, location.href), { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) {
        let detail = "No se pudo descargar la copia.";
        try { detail = (await response.json()).detail || detail; } catch { /* preserve generic error */ }
        throw { status: response.status, detail };
      }
      objectUrl = URL.createObjectURL(await response.blob());
      const link = node("a", null, { href: objectUrl, download: `opnsense-${id}.xml` });
      document.body.append(link); link.click(); link.remove();
      notice("#backup-status", "Descarga XML iniciada. Guarda el archivo en una ubicación privada.");
    } catch (error) { notice("#backup-error", failureText(error)); }
    finally { if (objectUrl) URL.revokeObjectURL(objectUrl); backups.busy = false; controls(); }
  }
  function openOperation() {
    state.fields = state.resource.fields || []; state.values = {}; state.editing = true;
    state.loaded = true; state.readOnly = state.catalogReadOnly || state.resource.read_only === true;
    $("#editor").hidden = false; $("#editor-title").textContent = state.resource.method === "GET" ? "Consultar estado" : "Preparar operación";
    $("#editor-help").textContent = state.resource.method === "GET" ? "Consulta la información actual del firewall."
      : "La operación se enviará al firewall solo cuando pulses Ejecutar y confirmes la acción.";
    $("#delete-item").hidden = true;
    renderFields(); controls();
  }
  function renderOperationResult(result) {
    $("#operation-output").hidden = false;
    const root = $("#operation-result"); root.replaceChildren();
    if (Array.isArray(result) && result.every(row => row && typeof row === "object" && !Array.isArray(row))) {
      const keys = [...new Set(result.flatMap(row => Object.keys(row)))];
      const table = node("table"), head = node("tr"), body = node("tbody");
      for (const key of keys) head.append(node("th", key, { scope: "col" }));
      const thead = node("thead"); thead.append(head); table.append(thead);
      for (const row of result) { const tr = node("tr"); for (const key of keys) tr.append(node("td", typeof row[key] === "object" ? JSON.stringify(row[key]) : row[key] ?? "—")); body.append(tr); }
      table.append(body); root.append(table);
      if (!result.length) root.append(node("p", "La consulta no devolvió registros.", { class: "muted" }));
    } else if (result && typeof result === "object" && !Array.isArray(result)) {
      const list = node("dl", null, { class: "result-details" });
      for (const [key, value] of Object.entries(result)) { list.append(node("dt", key), node("dd", value !== null && typeof value === "object" ? JSON.stringify(value, null, 2) : value ?? "—")); }
      root.append(list);
    } else root.append(node("pre", typeof result === "string" ? result : JSON.stringify(result ?? "")));
  }
  async function operate() {
    if (!state.resource?.operation || !writable()) return;
    const read = state.resource.method === "GET";
    if (!read && !confirm(typeof state.resource.confirm === "string" ? state.resource.confirm : `¿Ejecutar ${state.resource.label} en el firewall?`)) return;
    state.writing = true; controls(); notice("#editor-error", ""); notice("#result-status", "");
    try {
      const result = await api("operate", read ? { operation: state.resource.id, ...state.values } : {},
        read ? undefined : { operation: state.resource.id, values: { ...state.values } });
      renderOperationResult(result.result ?? result.state ?? {});
      $("#operation-output-title").textContent = read ? "Resultado de la consulta" : "Resultado de la operación";
      if (read) notice("#result-status", "Consulta completada.");
      else if (result.verified === true) { state.dirty = false; notice("#result-status", "Operación confirmada y verificada."); }
      else {
        state.reconcile = true;
        notice("#reconcile-warning", result.accepted === true ? "Enviada; resultado pendiente de verificar. Revisa el estado del firewall antes de ejecutar otra operación." : "No se confirmó el resultado. Revisa el estado del firewall antes de ejecutar otra operación.");
      }
    } catch (error) {
      notice("#editor-error", failureText(error));
      if (!read && (error.partial === true || ![400, 401, 403, 404, 409, 422].includes(error.status))) {
        state.reconcile = true; notice("#reconcile-warning", "El resultado es incierto. Comprueba el estado antes de ejecutar otra operación.");
      }
    } finally { clearSecrets(); state.writing = false; controls(); }
  }
  function fieldOptions(field) {
    if (Array.isArray(field.options)) return field.options.map(option => typeof option === "object"
      ? { value: String(option.value ?? option.id ?? ""), label: String(option.label ?? option.value ?? option.id ?? "") }
      : { value: String(option), label: String(option) });
    return Object.entries(field.options || {}).map(([value, option]) => ({ value, label: typeof option === "object" ? option.label || option.value || value : String(option) }));
  }
  function renderFields() {
    const fields = [];
    state.fields.forEach((field, index) => {
      const kind = field.secret ? "password" : field.kind || "text";
      const multiple = kind === "multiselect" || field.multiple === true;
      const label = node("label", null, { class: `field${kind === "textarea" ? " wide" : ""}${kind === "boolean" ? " boolean" : ""}`, for: `field-${index}` });
      label.append(node("span", `${field.label || field.name}${field.required && kind !== "boolean" && !(kind === "password" && state.uuid) ? " *" : ""}`));
      const input = node(kind === "textarea" ? "textarea" : kind === "select" || multiple ? "select" : "input", null,
        { id: `field-${index}`, name: field.name, autocomplete: kind === "password" ? "new-password" : "off" });
      if (input.tagName === "INPUT") input.type = kind === "boolean" ? "checkbox" : ["number", "integer"].includes(kind) ? "number" : kind === "password" ? "password" : "text";
      const value = state.values[field.name] ?? field.default ?? "";
      if (input.tagName === "SELECT") {
        input.multiple = multiple;
        const options = fieldOptions(field);
        const values = multiple ? Array.isArray(value) ? value.map(String) : String(value).split(",").filter(Boolean) : [String(value)];
        for (const selected of values) if (!options.some(option => option.value === selected)) options.push({ value: selected, label: selected || "Sin seleccionar" });
        if (!multiple && !options.some(option => option.value === "")) options.unshift({ value: "", label: "Selecciona una opción" });
        for (const option of options) {
          const element = node("option", option.label, { value: option.value }); element.selected = values.includes(option.value); input.append(element);
        }
      } else if (kind === "boolean") input.checked = value === true || value === 1 || value === "1";
      else input.value = kind === "password" ? "" : String(value);
      // Required BooleanField means a value is present, not that it must be true.
      input.required = !!field.required && kind !== "boolean" && !(kind === "password" && state.uuid);
      if (field.readonly || field.read_only) { input.disabled = true; input.required = false; }
      if (field.min !== undefined) input.min = String(field.min);
      if (field.max !== undefined) input.max = String(field.max);
      if (kind === "integer") input.step = "1";
      input.addEventListener("input", () => {
        state.values[field.name] = kind === "boolean" ? input.checked : multiple ? [...input.selectedOptions].map(option => option.value)
          : ["number", "integer"].includes(kind) && input.value !== "" ? Number(input.value) : input.value;
        state.dirty = true; controls();
      });
      label.append(input);
      const hint = kind === "password" ? state.uuid ? "Deja vacío para conservar el secreto existente." : "El valor no se mostrará después de guardarlo."
        : field.help || (multiple ? "Selecciona una o varias opciones con Ctrl o Cmd." : "");
      if (hint) label.append(node("span", hint, { class: "hint" }));
      fields.push(label);
      // Submit explicit normalized defaults, not untouched option objects.
      state.values[field.name] = kind === "password" ? "" : kind === "boolean" ? input.checked : multiple
        ? [...input.selectedOptions].map(option => option.value) : ["number", "integer"].includes(kind) && input.value !== "" ? Number(input.value) : input.value;
    });
    $("#entry-fields").replaceChildren(...fields);
  }
  async function openEditor(uuid = "") {
    if (!allowDiscard() || !state.loaded || (!uuid && !writable())) return;
    const epoch = state.epoch;
    state.loadingDetail = true; controls();
    notice("#editor-error", ""); notice("#result-status", "");
    $("#editor").hidden = false; $("#editor-title").textContent = "Consultando detalle…";
    try {
      const data = await api("manage", { resource: state.resource.id, ...(uuid ? { uuid } : { defaults: 1 }) });
      if (epoch !== state.epoch) return;
      if (!data.item || !Array.isArray(data.fields) || (uuid && !data.revision)) throw { status: 502, detail: "No se recibió un detalle editable completo." };
      state.fields = data.fields; state.values = { ...data.item }; state.uuid = uuid;
      state.revision = data.revision || ""; state.editing = true; state.dirty = false;
      if (data.read_only === true) state.readOnly = true;
      $("#editor-title").textContent = uuid ? "Detalle de la entrada" : "Nueva entrada";
      $("#editor-help").textContent = uuid ? "Los campos secretos se conservan si los dejas vacíos. Los cambios de otros administradores se comprueban antes de guardar." : "Los campos marcados con * son obligatorios. Revisa los valores antes de aplicar.";
      $("#delete-item").hidden = !uuid || !supports("delete");
      renderFields();
    } catch (error) {
      if (epoch !== state.epoch) return;
      state.editing = false; $("#editor-title").textContent = "Detalle no disponible";
      $("#entry-fields").replaceChildren(); state.fields = []; state.values = {}; state.uuid = ""; state.revision = "";
      notice("#editor-error", failureText(error));
    } finally {
      if (epoch === state.epoch) {
        state.loadingDetail = false; controls();
        if (!state.editing) $("#save-item").disabled = true;
        $("#editor").scrollIntoView({ block: "nearest" });
        if (state.editing) $("#entry-fields input, #entry-fields select, #entry-fields textarea")?.focus();
        else $("#editor-error").focus();
      }
    }
  }
  function clearSecrets() {
    for (const field of state.fields) if (field.secret || field.kind === "password") {
      state.values[field.name] = "";
      for (const input of $("#entry-fields").querySelectorAll("input")) if (input.name === field.name) input.value = "";
    }
  }
  async function write(action) {
    if (!writable() || !state.editing || !supports(action)) return;
    if (action === "delete" && !confirm("¿Eliminar esta entrada y aplicar el cambio en el firewall?")) return;
    const values = Object.fromEntries(state.fields.filter(field => !field.readonly && !field.read_only)
      .map(field => [field.name, state.values[field.name]]));
    const body = { resource: state.resource.id, action, ...(state.uuid ? { uuid: state.uuid, revision: state.revision } : {}),
      ...(action === "delete" ? {} : { values }) };
    state.writing = true; controls(); notice("#editor-error", ""); notice("#result-status", "");
    try {
      const result = await api("manage", {}, body);
      const savedOnly = result.config_saved === true && result.applied === false && result.verified === true;
      if ((!savedOnly && result.applied !== true) || result.verified !== true || result.partial === true || result.ok === false) {
        throw { status: 502, partial: true, uuid: result.uuid,
          detail: result.detail || "No se confirmó la aplicación y verificación completas." };
      }
      state.writing = false; closeEditor();
      const secretNote = result.secret_change_acknowledged === true && result.secret_verified === false
        ? " Credencial guardada; no se ha probado el acceso con ella." : "";
      notice("#result-status", (savedOnly ? "Configuración guardada y verificada; no requiere aplicar un servicio."
        : "Cambio aplicado y verificado en el firewall.") + secretNote);
      await loadList();
    } catch (error) {
      const detail = error.data || error;
      const definitelyRejected = [400, 401, 403, 404, 409, 422].includes(error.status) && error.partial !== true && detail.partial !== true;
      state.reconcile = !definitelyRejected;
      notice("#editor-error", failureText(error));
      if (state.reconcile) notice("#reconcile-warning", `La operación pudo haberse guardado${detail.uuid ? ` (UUID: ${detail.uuid})` : ""}. Los cambios están bloqueados para evitar duplicados. Actualiza la lista y revisa el estado del firewall antes de iniciar otro cambio.`);
      $("#editor-error").focus();
    } finally {
      clearSecrets(); state.writing = false; controls();
    }
  }
  $("#module-search").addEventListener("input", renderNavigation);
  $("#refresh-list").addEventListener("click", () => state.resource?.backup ? loadBackups() : loadList());
  $("#backup-create").addEventListener("click", () => mutateBackup("create"));
  $("#backup-reconcile").addEventListener("click", () => {
    if (!backups.busy && backups.loaded && confirm("¿Revisaste las copias existentes? No se repetirá la operación anterior.")) {
      backups.uncertain = false; notice("#backup-status", ""); controls();
    }
  });
  $("#new-item").addEventListener("click", () => openEditor());
  $("#prev-page").addEventListener("click", () => loadList(state.page - 1));
  $("#next-page").addEventListener("click", () => loadList(state.page + 1));
  $("#list-search-form").addEventListener("submit", event => { event.preventDefault(); if (locked()) return; state.query = $("#list-search").value.trim(); loadList(1); });
  $("#entry-form").addEventListener("submit", event => { event.preventDefault(); if (state.resource?.operation) operate(); else write(state.uuid ? "update" : "create"); });
  $("#delete-item").addEventListener("click", () => write("delete"));
  $("#cancel-edit").addEventListener("click", () => { if (allowDiscard()) { closeEditor(); if (state.resource?.operation) openOperation(); } });
  $("#reconcile").addEventListener("click", () => {
    if (locked() || state.listing || !confirm("¿Revisaste el estado real del firewall y sus nodos? Se descartará este borrador; no se repetirá la operación.")) return;
    state.reconcile = false; closeEditor(); if (state.resource?.operation) openOperation();
  });
  $("#back-panel").addEventListener("click", event => { if (!allowDiscard()) event.preventDefault(); });
  window.addEventListener("beforeunload", event => { if (state.dirty || state.writing || state.reconcile) { event.preventDefault(); event.returnValue = ""; } });
  window.addEventListener("hashchange", async () => {
    let id;
    try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
    const resource = navigationItems().find(item => item.id === id);
    if (resource) await selectResource(resource);
    if (state.resource && state.resource.id !== id) history.replaceState(null, "", `${location.pathname}${location.search}#${encodeURIComponent(state.resource.id)}`);
  });
  async function boot() {
    try {
      const data = await api("catalog");
      if (!Array.isArray(data.resources)) throw { status: 502, detail: "El catálogo recibido no es válido." };
      state.resources = data.resources; state.operations = (data.operations || []).map(operation => ({ ...operation, operation: true })); state.catalogReadOnly = data.read_only !== false;
      backups.available = data.backups?.available === true;
      renderNavigation();
      let id = "";
      try { id = decodeURIComponent(location.hash.slice(1)); } catch { /* invalid deep link keeps the catalog */ }
      const resource = navigationItems().find(item => item.id === id);
      if (resource) await selectResource(resource);
    } catch (error) {
      notice("#catalog-error", failureText(error)); $("#module-count").textContent = "Catálogo no disponible";
      $("#access-mode").textContent = "Acceso no confirmado";
    }
  }
  boot();
})();
