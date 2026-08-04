function showFatalError(msg) {
  const b = document.getElementById('fatalBanner');
  if (!b) { alert(msg); return; }
  b.innerHTML = '<b>Помилка:</b> ' + msg;
  b.classList.add('show');
}

window.addEventListener('error', (e) => {
  showFatalError((e && e.message) ? e.message : 'Невідома помилка виконання скрипта.');
});
window.addEventListener('unhandledrejection', (e) => {
  showFatalError((e && e.reason && e.reason.message) ? e.reason.message : 'Помилка під час виконання дії.');
});

(() => {
  "use strict";

  if (!window.crypto || !window.crypto.subtle) {
    showFatalError(
      'Браузер/режим перегляду не надає доступ до функцій шифрування (crypto.subtle). ' +
      'Це трапляється, коли файл відкрито в режимі попереднього перегляду, а не в самому браузері. ' +
      'Відкрийте цей файл безпосередньо в Chrome або Safari (див. підказку нижче на екрані).'
    );
    return;
  }

  // ---------------- State (in-memory only, never persisted to browser storage) ----------------
  let vaultKey = null;        // CryptoKey
  let vaultSalt = null;       // Uint8Array
  let vaultIterations = 250000;
  let vaultRecords = [];      // [{id,name,login,email,password,notes,updated}]
  let dirty = false;
  let editingId = null;       // id of record being edited, or null for "new"
  let pendingMode = null;     // 'new' | 'open'
  let pendingFileMeta = null; // parsed vault file JSON when opening

  // ---------------- Utility ----------------
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toast._h);
    toast._h = setTimeout(() => t.classList.remove('show'), 2200);
  }

  function b64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function unb64(str) {
    const s = atob(str);
    const bytes = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes;
  }
  function uid() {
    return 'r_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
  }

  function setDirty(v) {
    dirty = v;
    $('dirtyDot').classList.toggle('show', v);
  }

  // ---------------- Crypto ----------------
  async function deriveKey(password, salt, iterations) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptRecords(key, records) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = enc.encode(JSON.stringify(records));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return { iv, ciphertext };
  }

  async function decryptRecords(key, iv, ciphertext) {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(dec.decode(plaintext));
  }

  function generatePassword(length = 20) {
    const sets = {
      lower: 'abcdefghijkmnopqrstuvwxyz',
      upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
      digits: '23456789',
      symbols: '!@#$%^&*()-_=+[]{}?'
    };
    const all = sets.lower + sets.upper + sets.digits + sets.symbols;
    const randVals = crypto.getRandomValues(new Uint32Array(length));
    let pwd = [sets.lower, sets.upper, sets.digits, sets.symbols].map(set => {
      const r = crypto.getRandomValues(new Uint32Array(1))[0];
      return set[r % set.length];
    });
    for (let i = pwd.length; i < length; i++) {
      pwd.push(all[randVals[i] % all.length]);
    }
    // shuffle
    for (let i = pwd.length - 1; i > 0; i--) {
      const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
      [pwd[i], pwd[j]] = [pwd[j], pwd[i]];
    }
    return pwd.join('');
  }

  // ---------------- Screen switching ----------------
  function showScreen(id) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    $(id).classList.add('active');
  }

  function resetLockUI() {
    $('lockChoice').hidden = false;
    $('passwordPrompt').hidden = true;
    $('masterPasswordConfirm').hidden = true;
    $('masterPasswordInput').value = '';
    $('masterPasswordConfirm').value = '';
    $('lockError').textContent = '';
    $('openingFileName').textContent = '';
    $('dialHandle').classList.remove('spin');
    pendingMode = null;
    pendingFileMeta = null;
  }

  // ---------------- New vault flow ----------------
  $('btnNewVault').addEventListener('click', () => {
    pendingMode = 'new';
    $('lockChoice').hidden = true;
    $('passwordPrompt').hidden = false;
    $('masterPasswordConfirm').hidden = false;
    $('masterPasswordInput').placeholder = 'Новий майстер-пароль';
    $('masterPasswordInput').focus();
  });

  // ---------------- Open vault flow ----------------
  $('btnOpenVault').addEventListener('click', () => $('fileInput').click());
  $('fileInput').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      if (!parsed.salt || !parsed.iv || !parsed.data) throw new Error('bad file');
      pendingFileMeta = parsed;
      pendingMode = 'open';
      $('lockChoice').hidden = true;
      $('passwordPrompt').hidden = false;
      $('masterPasswordConfirm').hidden = true;
      $('masterPasswordInput').placeholder = 'Майстер-пароль';
      $('openingFileName').textContent = 'Файл: ' + file.name;
      $('masterPasswordInput').focus();
    } catch (err) {
      $('lockError').textContent = 'Не вдалося прочитати файл сховища. Перевірте, що це правильний файл.';
    }
    e.target.value = '';
  });

  $('btnCancelPassword').addEventListener('click', resetLockUI);

  $('btnConfirmPassword').addEventListener('click', handleConfirmPassword);
  $('masterPasswordInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') handleConfirmPassword(); });
  $('masterPasswordConfirm').addEventListener('keydown', (e) => { if (e.key === 'Enter') handleConfirmPassword(); });

  async function handleConfirmPassword() {
    const pwd = $('masterPasswordInput').value;
    $('lockError').textContent = '';
    if (!pwd || pwd.length < 4) {
      $('lockError').textContent = 'Пароль закороткий (мінімум 4 символи, рекомендовано довший).';
      return;
    }

    if (pendingMode === 'new') {
      const confirmPwd = $('masterPasswordConfirm').value;
      if (pwd !== confirmPwd) {
        $('lockError').textContent = 'Паролі не збігаються.';
        return;
      }
      vaultSalt = crypto.getRandomValues(new Uint8Array(16));
      vaultIterations = 250000;
      vaultKey = await deriveKey(pwd, vaultSalt, vaultIterations);
      vaultRecords = [];
      setDirty(false);
      enterVault();
      toast('Нове сховище створено. Не забудьте зберегти файл.');
    } else if (pendingMode === 'open') {
      try {
        const salt = unb64(pendingFileMeta.salt);
        const iv = unb64(pendingFileMeta.iv);
        const ciphertext = unb64(pendingFileMeta.data);
        const iterations = pendingFileMeta.iterations || 250000;
        const key = await deriveKey(pwd, salt, iterations);
        const records = await decryptRecords(key, iv, ciphertext);
        vaultKey = key;
        vaultSalt = salt;
        vaultIterations = iterations;
        vaultRecords = records;
        setDirty(false);
        enterVault();
        toast('Сховище розблоковано.');
      } catch (err) {
        $('lockError').textContent = 'Невірний пароль або пошкоджений файл.';
      }
    }
  }

  function enterVault() {
    $('dialHandle').classList.add('spin');
    setTimeout(() => {
      showScreen('vaultScreen');
      renderRecords();
      resetLockUI();
      // resetLockUI clears lockChoice visibility state for next time we come back
    }, 350);
  }

  // ---------------- Lock ----------------
  $('btnLock').addEventListener('click', () => {
    if (dirty) {
      const ok = confirm('У вас є незбережені зміни. Заблокувати без збереження?');
      if (!ok) return;
    }
    vaultKey = null;
    vaultSalt = null;
    vaultRecords = [];
    editingId = null;
    setDirty(false);
    showScreen('lockScreen');
  });

  // ---------------- Save vault to file ----------------
  $('btnSaveVault').addEventListener('click', async () => {
    if (!vaultKey) return;
    const { iv, ciphertext } = await encryptRecords(vaultKey, vaultRecords);
    const fileObj = {
      app: 'local-password-vault',
      version: 1,
      iterations: vaultIterations,
      salt: b64(vaultSalt),
      iv: b64(iv),
      data: b64(ciphertext)
    };
    const blob = new Blob([JSON.stringify(fileObj)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `vault-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setDirty(false);
    toast('Файл сховища збережено (перевірте завантаження).');
  });

  // ---------------- Change master password ----------------
  $('btnChangeMaster').addEventListener('click', async () => {
    const newPwd = prompt('Введіть новий майстер-пароль:');
    if (!newPwd) return;
    if (newPwd.length < 4) { toast('Пароль закороткий.'); return; }
    const confirmPwd = prompt('Повторіть новий майстер-пароль:');
    if (newPwd !== confirmPwd) { toast('Паролі не збігаються.'); return; }
    vaultSalt = crypto.getRandomValues(new Uint8Array(16));
    vaultIterations = 250000;
    vaultKey = await deriveKey(newPwd, vaultSalt, vaultIterations);
    setDirty(true);
    toast('Майстер-пароль змінено. Натисніть «Зберегти файл сховища», щоб застосувати.');
  });

  // ---------------- Records rendering ----------------
  function renderRecords() {
    const query = $('searchInput').value.trim().toLowerCase();
    const list = $('recordsList');
    const filtered = vaultRecords.filter(r => {
      if (!query) return true;
      return (r.name || '').toLowerCase().includes(query)
        || (r.login || '').toLowerCase().includes(query)
        || (r.email || '').toLowerCase().includes(query);
    }).sort((a, b) => (a.name || '').localeCompare(b.name || '', 'uk'));

    if (filtered.length === 0) {
      list.innerHTML = '';
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.innerHTML = vaultRecords.length === 0
        ? '<div class="serif">Тут поки порожньо</div><div>Додайте перший обліковий запис.</div>'
        : '<div class="serif">Нічого не знайдено</div><div>Спробуйте інший запит пошуку.</div>';
      list.appendChild(empty);
      return;
    }

    list.innerHTML = '';
    list.className = 'record-list';
    filtered.forEach(r => {
      const card = document.createElement('div');
      card.className = 'record-card';
      card.innerHTML = `
        <div class="record-main">
          <div class="record-name"></div>
          <div class="record-meta">
            ${r.login ? `<span><span class="label">логін</span> ${escapeHtml(r.login)}</span>` : ''}
            ${r.email ? `<span><span class="label">пошта</span> ${escapeHtml(r.email)}</span>` : ''}
          </div>
        </div>
        <div class="record-actions">
          <button class="icon-btn" data-act="copy-pwd" title="Копіювати пароль">🔑</button>
          <button class="icon-btn" data-act="edit" title="Редагувати">✎</button>
        </div>
      `;
      card.querySelector('.record-name').textContent = r.name || '(без назви)';
      card.querySelector('[data-act="copy-pwd"]').addEventListener('click', (ev) => {
        ev.stopPropagation();
        copyText(r.password || '', 'Пароль скопійовано');
      });
      card.querySelector('[data-act="edit"]').addEventListener('click', () => openModal(r.id));
      list.appendChild(card);
    });
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  async function copyText(text, msg) {
    try {
      await navigator.clipboard.writeText(text);
      toast(msg);
    } catch {
      toast('Не вдалося скопіювати автоматично.');
    }
  }

  $('searchInput').addEventListener('input', renderRecords);

  // ---------------- Modal (add/edit record) ----------------
  function openModal(id) {
    editingId = id || null;
    const record = id ? vaultRecords.find(r => r.id === id) : null;
    $('modalTitle').textContent = record ? 'Редагувати запис' : 'Новий запис';
    $('fName').value = record ? record.name || '' : '';
    $('fLogin').value = record ? record.login || '' : '';
    $('fEmail').value = record ? record.email || '' : '';
    $('fPassword').value = record ? record.password || '' : '';
    $('fPassword').type = 'password';
    $('fNotes').value = record ? record.notes || '' : '';
    $('btnDeleteRecord').hidden = !record;
    $('modalOverlay').hidden = false;
    setTimeout(() => $('fName').focus(), 30);
  }

  function closeModal() {
    $('modalOverlay').hidden = true;
    editingId = null;
  }

  $('btnAddRecord').addEventListener('click', () => openModal(null));
  $('btnCancelModal').addEventListener('click', closeModal);
  $('modalOverlay').addEventListener('click', (e) => { if (e.target.id === 'modalOverlay') closeModal(); });

  $('btnTogglePwd').addEventListener('click', () => {
    const f = $('fPassword');
    f.type = f.type === 'password' ? 'text' : 'password';
  });
  $('btnGenPwd').addEventListener('click', () => {
    $('fPassword').type = 'text';
    $('fPassword').value = generatePassword(20);
  });

  $('btnSaveRecord').addEventListener('click', () => {
    const name = $('fName').value.trim();
    if (!name) { toast('Вкажіть назву облікового запису.'); $('fName').focus(); return; }
    const data = {
      name,
      login: $('fLogin').value.trim(),
      email: $('fEmail').value.trim(),
      password: $('fPassword').value,
      notes: $('fNotes').value.trim(),
      updated: new Date().toISOString()
    };
    if (editingId) {
      const idx = vaultRecords.findIndex(r => r.id === editingId);
      if (idx !== -1) vaultRecords[idx] = { ...vaultRecords[idx], ...data };
    } else {
      vaultRecords.push({ id: uid(), ...data });
    }
    setDirty(true);
    renderRecords();
    closeModal();
    toast('Запис збережено. Не забудьте зберегти файл сховища.');
  });

  $('btnDeleteRecord').addEventListener('click', () => {
    if (!editingId) return;
    const ok = confirm('Видалити цей запис?');
    if (!ok) return;
    vaultRecords = vaultRecords.filter(r => r.id !== editingId);
    setDirty(true);
    renderRecords();
    closeModal();
    toast('Запис видалено.');
  });

  // Warn before leaving with unsaved changes
  window.addEventListener('beforeunload', (e) => {
    if (dirty) { e.preventDefault(); e.returnValue = ''; }
  });

})();

// ---------------- PWA: service worker registration ----------------
// Registers the offline cache so the app works with no network at all
// after the very first load. Safe no-op if unsupported (e.g. very old browsers).
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('service-worker.js').catch(() => {
      // Non-fatal: app still works, just without offline install/caching.
    });
  });
}
