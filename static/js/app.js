/**
 * SecurePass Web Dashboard Client Script.
 * Interacts with Flask REST API endpoints:
 * - POST /api/generate
 * - POST /api/analyze
 * - POST /api/hash
 * - POST /api/verify
 * - GET/POST/DELETE /api/vault
 * - GET /api/audit-logs
 * - GET /api/health
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- System Status Check ---
    checkSystemHealth();

    // --- Tab Switching Navigation ---
    setupTabs();

    // --- Tab 1: Generator Setup ---
    setupGenerator();

    // --- Tab 2: PBKDF2 Hasher Setup ---
    setupHasher();

    // --- Tab 3: Vault Setup ---
    setupVault();

    // --- Tab 5: Audit Log Setup ---
    setupAuditLog();
});

// --- Health Check ---
async function checkSystemHealth() {
    try {
        const res = await fetch('/api/health');
        if (res.ok) {
            const data = await res.json();
            const badgeC = document.getElementById('badge-c');
            if (data.c_engine_loaded) {
                badgeC.innerHTML = '<span class="indicator"></span> C Engine: Active (' + (data.c_library_file ? data.c_library_file.split('\\').pop() : 'libentropy.dll') + ')';
                badgeC.className = 'badge badge-c';
            } else {
                badgeC.innerHTML = '<span class="indicator" style="background:#e3b341;box-shadow:0 0 6px #e3b341"></span> C Engine: Fallback (Python)';
                badgeC.className = 'badge badge-db';
            }
        }
    } catch (err) {
        console.warn('Health check error:', err);
    }
}

// --- Tab Navigation ---
function setupTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const targetId = btn.getAttribute('data-tab');
            const targetPane = document.getElementById(targetId);
            if (targetPane) targetPane.classList.add('active');

            // Trigger data refresh if entering Vault or Audit tab
            if (targetId === 'tab-vault') loadVaultItems();
            if (targetId === 'tab-audit') loadAuditLogs();
        });
    });
}

// --- Generator Logic ---
let currentGeneratedPassword = '';

function setupGenerator() {
    const lengthSlider = document.getElementById('length-slider');
    const lengthVal = document.getElementById('length-val');
    const wordsSlider = document.getElementById('words-slider');
    const wordsVal = document.getElementById('words-val');

    const chkUpper = document.getElementById('chk-upper');
    const chkLower = document.getElementById('chk-lower');
    const chkDigits = document.getElementById('chk-digits');
    const chkSymbols = document.getElementById('chk-symbols');
    const chkAmbiguous = document.getElementById('chk-ambiguous');
    const customExclude = document.getElementById('custom-exclude');

    const btnGenerate = document.getElementById('btn-generate');
    const btnBatch = document.getElementById('btn-batch-generate');
    const btnCopy = document.getElementById('btn-copy');
    const btnSaveVaultQuick = document.getElementById('btn-save-vault-quick');

    const modeRadios = document.querySelectorAll('input[name="gen-mode"]');
    const standardControls = document.getElementById('standard-controls');
    const passphraseControls = document.getElementById('passphrase-controls');

    // Update Slider text
    lengthSlider.addEventListener('input', (e) => {
        lengthVal.textContent = e.target.value;
    });
    wordsSlider.addEventListener('input', (e) => {
        wordsVal.textContent = e.target.value;
    });

    // Mode Toggle
    modeRadios.forEach(radio => {
        radio.addEventListener('change', () => {
            if (radio.value === 'passphrase') {
                standardControls.style.display = 'none';
                passphraseControls.style.display = 'block';
            } else {
                standardControls.style.display = 'block';
                passphraseControls.style.display = 'none';
            }
        });
    });

    // Generate Single Password
    async function doGenerate() {
        const isPassphrase = document.querySelector('input[name="gen-mode"]:checked').value === 'passphrase';
        let payload = {};

        if (isPassphrase) {
            payload = {
                mode: 'passphrase',
                word_count: parseInt(wordsSlider.value),
                separator: document.getElementById('passphrase-sep').value || '-',
                capitalize: document.getElementById('chk-capitalize').checked,
                include_number: document.getElementById('chk-passphrase-num').checked
            };
        } else {
            payload = {
                mode: 'password',
                length: parseInt(lengthSlider.value),
                include_uppercase: chkUpper.checked,
                include_lowercase: chkLower.checked,
                include_digits: chkDigits.checked,
                include_symbols: chkSymbols.checked,
                exclude_ambiguous: chkAmbiguous.checked,
                custom_exclude: customExclude.value.trim() || null,
                count: 1
            };
        }

        try {
            const res = await fetch('/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await res.json();
            if (res.ok) {
                currentGeneratedPassword = data.password;
                document.getElementById('password-output').textContent = data.password;
                document.getElementById('batch-container').style.display = 'none';
                renderAnalysis(data.analysis);
            } else {
                alert('Generation Error: ' + (data.error || 'Unknown error'));
            }
        } catch (err) {
            console.error('Fetch error:', err);
            alert('Failed to connect to backend REST server.');
        }
    }

    btnGenerate.addEventListener('click', doGenerate);

    // Batch Generation
    btnBatch.addEventListener('click', async () => {
        const payload = {
            mode: 'password',
            length: parseInt(lengthSlider.value),
            include_uppercase: chkUpper.checked,
            include_lowercase: chkLower.checked,
            include_digits: chkDigits.checked,
            include_symbols: chkSymbols.checked,
            exclude_ambiguous: chkAmbiguous.checked,
            custom_exclude: customExclude.value.trim() || null,
            count: 5
        };

        try {
            const res = await fetch('/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await res.json();
            if (res.ok && data.passwords && data.passwords.length > 0) {
                currentGeneratedPassword = data.passwords[0].password;
                document.getElementById('password-output').textContent = currentGeneratedPassword;
                renderAnalysis(data.passwords[0].analysis);

                // Render Batch List
                const batchContainer = document.getElementById('batch-container');
                const batchList = document.getElementById('batch-list');
                batchList.innerHTML = '';
                data.passwords.forEach(item => {
                    const div = document.createElement('div');
                    div.className = 'batch-item';
                    div.innerHTML = `
                        <span>${escapeHtml(item.password)}</span>
                        <span class="badge">${item.analysis.strength_label} (${item.analysis.shannon_entropy_bits} bits)</span>
                    `;
                    div.style.cursor = 'pointer';
                    div.title = 'Click to select this password';
                    div.addEventListener('click', () => {
                        currentGeneratedPassword = item.password;
                        document.getElementById('password-output').textContent = item.password;
                        renderAnalysis(item.analysis);
                    });
                    batchList.appendChild(div);
                });
                batchContainer.style.display = 'block';
            }
        } catch (err) {
            alert('Batch generation failed: ' + err);
        }
    });

    // Copy to Clipboard
    btnCopy.addEventListener('click', () => {
        if (!currentGeneratedPassword) return;
        navigator.clipboard.writeText(currentGeneratedPassword).then(() => {
            const orig = btnCopy.innerHTML;
            btnCopy.innerHTML = '✓';
            setTimeout(() => btnCopy.innerHTML = orig, 1200);
        });
    });

    // Quick Save to Vault Button
    btnSaveVaultQuick.addEventListener('click', () => {
        if (!currentGeneratedPassword) return;
        document.querySelector('[data-tab="tab-vault"]').click();
        document.getElementById('vault-password').value = currentGeneratedPassword;
        document.getElementById('vault-service').focus();
    });

    // Initial generation on page load
    doGenerate();
}

function renderAnalysis(analysis) {
    if (!analysis) return;

    // Strength Meter & Labels
    const score = analysis.strength_score || 0;
    const label = analysis.strength_label || 'Moderate';
    document.getElementById('strength-score').textContent = score;
    document.getElementById('strength-label').textContent = label;

    const bar = document.getElementById('strength-bar');
    bar.style.width = score + '%';

    if (score < 30) {
        bar.style.backgroundColor = 'var(--accent-red)';
    } else if (score < 60) {
        bar.style.backgroundColor = 'var(--accent-yellow)';
    } else if (score < 85) {
        bar.style.backgroundColor = 'var(--accent-green)';
    } else {
        bar.style.backgroundColor = 'var(--accent-cyan)';
    }

    // Numerical Metrics
    document.getElementById('metric-shannon').innerHTML = `${analysis.shannon_entropy_bits} <span class="unit">bits</span>`;
    document.getElementById('metric-pool').innerHTML = `${analysis.pool_entropy_bits} <span class="unit">bits</span>`;
    document.getElementById('metric-crack-time').textContent = analysis.crack_time_human || '--';

    // Character breakdowns
    document.getElementById('tag-upper').textContent = `Upper: ${analysis.uppercase_count}`;
    document.getElementById('tag-lower').textContent = `Lower: ${analysis.lowercase_count}`;
    document.getElementById('tag-digit').textContent = `Digits: ${analysis.digit_count}`;
    document.getElementById('tag-sym').textContent = `Symbols: ${analysis.symbol_count}`;
    document.getElementById('tag-pool').textContent = `Pool: ${analysis.pool_size}`;

    // Engine Badge
    const cBadge = document.getElementById('c-badge-status');
    if (analysis.engine && analysis.engine.includes('Native C')) {
        cBadge.textContent = 'Native C Library (ctypes)';
        cBadge.className = 'badge badge-c';
    } else {
        cBadge.textContent = 'Python Fallback';
        cBadge.className = 'badge badge-db';
    }
}

// --- PBKDF2 Hasher & Verifier ---
function setupHasher() {
    const btnHash = document.getElementById('btn-hash-now');
    const inputPw = document.getElementById('hash-input-password');
    const iterSlider = document.getElementById('hash-iterations');
    const iterVal = document.getElementById('iter-val');

    iterSlider.addEventListener('input', (e) => {
        iterVal.textContent = Number(e.target.value).toLocaleString();
    });

    btnHash.addEventListener('click', async () => {
        const pw = inputPw.value;
        if (!pw) {
            alert('Please enter a password to hash.');
            return;
        }

        try {
            const res = await fetch('/api/hash', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    password: pw,
                    iterations: parseInt(iterSlider.value),
                    algorithm: 'sha256'
                })
            });

            const data = await res.json();
            if (res.ok) {
                document.getElementById('hash-results-box').style.display = 'block';
                document.getElementById('disp-salt').textContent = data.salt_hex;
                document.getElementById('disp-hash').textContent = data.hash_hex;
                document.getElementById('disp-encoded').textContent = data.encoded;

                // Auto-fill verifier fields for convenience
                document.getElementById('verify-candidate-password').value = pw;
                document.getElementById('verify-encoded-string').value = data.encoded;
            } else {
                alert('Hash failed: ' + data.error);
            }
        } catch (err) {
            alert('Server error: ' + err);
        }
    });

    // Verifier
    const btnVerify = document.getElementById('btn-verify-now');
    const banner = document.getElementById('verify-status-banner');

    btnVerify.addEventListener('click', async () => {
        const candidate = document.getElementById('verify-candidate-password').value;
        const encoded = document.getElementById('verify-encoded-string').value.trim();

        if (!candidate || !encoded) {
            alert('Please provide candidate password and encoded hash string.');
            return;
        }

        try {
            const res = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    password: candidate,
                    encoded: encoded
                })
            });

            const data = await res.json();
            banner.style.display = 'flex';
            if (data.valid) {
                banner.className = 'status-banner success';
                banner.innerHTML = `
                    <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    <span><strong>Verification SUCCESS:</strong> Password matches hash! Constant-time comparison verified via secrets.compare_digest.</span>
                `;
            } else {
                banner.className = 'status-banner error';
                banner.innerHTML = `
                    <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                    <span><strong>Verification FAILED:</strong> Candidate password does NOT match the cryptographic hash.</span>
                `;
            }
        } catch (err) {
            alert('Verification request failed: ' + err);
        }
    });
}

// --- SQLite Vault Logic ---
function setupVault() {
    const vaultForm = document.getElementById('vault-form');
    const btnUseCurrent = document.getElementById('btn-vault-use-gen');
    const btnRefresh = document.getElementById('btn-refresh-vault');

    btnUseCurrent.addEventListener('click', () => {
        if (currentGeneratedPassword) {
            document.getElementById('vault-password').value = currentGeneratedPassword;
        } else {
            alert('Generate a password first in the Generator tab.');
        }
    });

    btnRefresh.addEventListener('click', loadVaultItems);

    vaultForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            service_name: document.getElementById('vault-service').value.trim(),
            username_or_email: document.getElementById('vault-username').value.trim(),
            password_value: document.getElementById('vault-password').value,
            category: document.getElementById('vault-category').value,
            notes: document.getElementById('vault-notes').value.trim()
        };

        try {
            const res = await fetch('/api/vault', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                vaultForm.reset();
                loadVaultItems();
            } else {
                const err = await res.json();
                alert('Save failed: ' + (err.error || 'Server error'));
            }
        } catch (err) {
            alert('Failed to save to SQLite: ' + err);
        }
    });
}

async function loadVaultItems() {
    try {
        const res = await fetch('/api/vault');
        const data = await res.json();
        const tbody = document.querySelector('#vault-table tbody');
        const countSpan = document.getElementById('vault-count');

        if (res.ok && data.vault) {
            countSpan.textContent = data.count;
            tbody.innerHTML = '';

            if (data.vault.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No items in SQLite vault yet. Add one!</td></tr>`;
                return;
            }

            data.vault.forEach(item => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${escapeHtml(item.service_name)}</strong></td>
                    <td class="font-mono text-sm">${escapeHtml(item.username_or_email)}</td>
                    <td class="font-mono text-sm">
                        <span class="pw-masked" id="pw-mask-${item.id}">••••••••••••</span>
                        <span class="pw-plain" id="pw-plain-${item.id}" style="display:none; color:#7ee787;">${escapeHtml(item.password_value)}</span>
                        <button class="btn-subtle btn-toggle-pw" data-id="${item.id}" style="margin-left:6px; padding:2px 6px;">Show</button>
                    </td>
                    <td><span class="badge">${escapeHtml(item.category || 'General')}</span></td>
                    <td class="text-muted text-sm">${escapeHtml(item.created_at || '')}</td>
                    <td>
                        <button class="btn-subtle btn-del-vault" data-id="${item.id}" style="color:#ff7b72;">Delete</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });

            // Bind toggle buttons
            document.querySelectorAll('.btn-toggle-pw').forEach(btn => {
                btn.addEventListener('click', () => {
                    const id = btn.getAttribute('data-id');
                    const mask = document.getElementById(`pw-mask-${id}`);
                    const plain = document.getElementById(`pw-plain-${id}`);
                    if (plain.style.display === 'none') {
                        plain.style.display = 'inline';
                        mask.style.display = 'none';
                        btn.textContent = 'Hide';
                    } else {
                        plain.style.display = 'none';
                        mask.style.display = 'inline';
                        btn.textContent = 'Show';
                    }
                });
            });

            // Bind delete buttons
            document.querySelectorAll('.btn-del-vault').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const id = btn.getAttribute('data-id');
                    if (confirm('Delete this saved credential from SQLite?')) {
                        await fetch(`/api/vault/${id}`, { method: 'DELETE' });
                        loadVaultItems();
                    }
                });
            });
        }
    } catch (err) {
        console.error('Failed to load vault items:', err);
    }
}

// --- Audit Log Logic ---
function setupAuditLog() {
    const btnRefresh = document.getElementById('btn-refresh-audit');
    btnRefresh.addEventListener('click', loadAuditLogs);
}

async function loadAuditLogs() {
    try {
        const res = await fetch('/api/audit-logs?limit=30');
        const data = await res.json();
        const tbody = document.querySelector('#audit-table tbody');

        if (res.ok && data.logs) {
            tbody.innerHTML = '';
            if (data.logs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No audit events logged yet.</td></tr>`;
                return;
            }

            data.logs.forEach(log => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="font-mono text-sm">${log.id}</td>
                    <td><span class="badge ${log.action.includes('FAIL') ? 'badge-db' : 'badge-crypto'}">${escapeHtml(log.action)}</span></td>
                    <td class="font-mono text-sm">${escapeHtml(log.ip_address || '127.0.0.1')}</td>
                    <td class="text-sm">${escapeHtml(log.details || '')}</td>
                    <td class="font-mono text-sm text-muted">${escapeHtml(log.timestamp || '')}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error('Failed to load audit logs:', err);
    }
}

// Security utility: escape HTML strings
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
