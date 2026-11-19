// The Wallet page of an EU Wallet gateway: certificates, credential types, trust anchors,
// provider server, settings, the one-step setup and the records (verifications or issued credentials).
const page = document.querySelector('[data-wallet-url]');
const walletUrl = page.dataset.walletUrl;
const isIssuer = page.dataset.role === 'issuer';

const reloadWith = (message) => {
    UI.flash(message);
    window.location.reload();
};

// "given_name", "address.locality?" -> { path: ['address', 'locality'], required: false }
const parseClaimLines = (value) => value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
    const optional = line.endsWith('?');
    return { path: (optional ? line.slice(0, -1) : line).split('.').map((part) => part.trim()).filter(Boolean), required: !optional };
});

UI.bindForm(document.getElementById('identityForm'), {
    alert: document.getElementById('identity-alert'),
    loadingLabel: 'Saving…',
    submit: async (formData) => {
        const body = {};
        for (const name of ['legalName', 'displayName', 'legalCategory', 'accessCertificatePem', 'accessKeyPem', 'issuerCertificatePem', 'issuerKeyPem', 'registrationCertificate']) {
            if (formData.has(name)) body[name] = formData.get(name);
        }
        await UI.sendJson(`${walletUrl}/identity`, { method: 'PUT', body });
        reloadWith('Saved. Private keys are stored encrypted.');
    },
});

UI.bindForm(document.getElementById('typeForm'), {
    alert: document.getElementById('type-alert'),
    loadingLabel: 'Adding…',
    submit: async (formData) => {
        await UI.sendJson(`${walletUrl}/types`, {
            body: {
                key: formData.get('key'),
                name: formData.get('name'),
                vct: formData.get('vct'),
                claims: parseClaimLines(formData.get('claims')),
                ...(isIssuer ? { validityDays: formData.get('validityDays') } : { anchorIds: formData.getAll('anchorIds') }),
            },
        });
        reloadWith('Credential type added');
    },
});

// The EU PID (PID rulebook, SD-JWT VC claim names).
document.querySelector('[data-pid-preset]')?.addEventListener('click', () => {
    const form = document.getElementById('typeForm');
    form.elements.key.value = 'pid';
    form.elements.name.value = 'Person identification data (PID)';
    form.elements.vct.value = 'urn:eudi:pid:1';
    form.elements.claims.value = ['given_name', 'family_name', 'birthdate', 'nationalities?', 'place_of_birth?', 'address.locality?', 'issuing_country?'].join('\n');
});

// A higher-education diploma. An example, not an EU rulebook: the issuer chooses the vct and the
// claim names, and a verifier copies them from the issuer's published type.
document.querySelector('[data-diploma-preset]')?.addEventListener('click', () => {
    const form = document.getElementById('typeForm');
    form.elements.key.value = 'diploma';
    form.elements.name.value = 'University diploma';
    form.elements.vct.value = isIssuer
        ? `${(page.dataset.publicUrl || 'https://university.example').replace(/\/+$/, '')}/credentials/diploma`
        : 'https://university.example/credentials/diploma';
    form.elements.claims.value = [
        'given_name', 'family_name', 'birthdate?', 'degree', 'field_of_study', 'awarding_institution', 'award_date', 'grade?', 'diploma_number?',
    ].join('\n');
    if (form.elements.validityDays) form.elements.validityDays.value = 3650;
    UI.toast(isIssuer ? 'Diploma filled in. Check the vct: wallets and verifiers will use it.' : "Diploma filled in. Replace the vct with the one the university's issuer publishes.");
});

UI.bindForm(document.getElementById('anchorForm'), {
    alert: document.getElementById('anchor-alert'),
    loadingLabel: 'Adding…',
    submit: async (formData) => {
        await UI.sendJson(`${walletUrl}/anchors`, {
            body: { name: formData.get('name'), entitlement: formData.get('entitlement'), certificatesPem: formData.get('certificatesPem') },
        });
        reloadWith('Trust anchor added');
    },
});

UI.bindForm(document.getElementById('providerForm'), {
    alert: document.getElementById('provider-alert'),
    loadingLabel: 'Saving…',
    submit: async (formData) => {
        await UI.sendJson(`${walletUrl}/settings`, {
            method: 'PUT',
            body: { provider: { connectionId: formData.get('connectionId'), callbackUrl: formData.get('callbackUrl'), claimsUrl: formData.get('claimsUrl') || '' } },
        });
        reloadWith('Provider server saved');
    },
});

document.querySelector('[data-callback-secret]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    const ok = await UI.confirm({
        title: 'Create a new callback secret?',
        message: 'The provider server must check X-Wallet-Signature with the new secret once the gateway has the next configuration.',
        confirmLabel: 'Create secret',
    });
    if (!ok) return;
    UI.setLoading(button, true, 'Creating…');
    try {
        const result = await UI.sendJson(`${walletUrl}/callback-secret`);
        const box = document.getElementById('secret-result');
        box.textContent = '';
        const label = document.createElement('p');
        label.textContent = 'Callback secret (shown once; copy it to the provider server):';
        const code = document.createElement('code');
        code.className = 'mono';
        code.textContent = result.callbackSecret;
        box.append(label, code);
        box.hidden = false;
    } catch (error) {
        UI.toast(error.message, 'error');
    } finally {
        UI.setLoading(button, false);
    }
});

UI.bindForm(document.getElementById('settingsForm'), {
    alert: document.getElementById('settings-alert'),
    loadingLabel: 'Saving…',
    submit: async (formData) => {
        const settings = {};
        for (const name of ['clientIdScheme', 'responseMode', 'sessionSeconds', 'resultRetentionHours', 'verifierInfoFormat', 'offerTtlSeconds', 'batchSize']) {
            if (formData.has(name)) settings[name] = formData.get(name);
        }
        const body = { settings };
        if (isIssuer) {
            settings.requireWalletAttestation = formData.get('requireWalletAttestation') === 'on';
            body.walletProviderAnchorIds = formData.getAll('walletProviderAnchorIds');
        }
        await UI.sendJson(`${walletUrl}/settings`, { method: 'PUT', body });
        reloadWith('Settings saved');
    },
});

document.querySelector('[data-wallet-setup]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    UI.setLoading(button, true, 'Setting up…');
    try {
        const result = await UI.sendJson(`${walletUrl}/setup`);
        const box = document.getElementById('setup-result');
        box.textContent = '';
        const line = (text) => {
            const p = document.createElement('p');
            p.textContent = text;
            box.append(p);
        };
        line(`API ${result.api.name} at ${result.api.basePath} in ${result.catalog.name}, product ${result.product.name}.`);
        line(`Provider server application: ${result.application.name}, client ID ${result.application.clientId}.`);
        if (result.application.clientSecret) line(`Client secret (shown once): ${result.application.clientSecret}`);
        line(result.attached ? 'The gateway serves this catalog.' : result.message);
        box.hidden = false;
        UI.toast('Wallet API set up');
    } catch (error) {
        UI.toast(error.message, 'error');
    } finally {
        UI.setLoading(button, false);
    }
});

const cell = (row, text, className) => {
    const td = document.createElement('td');
    td.textContent = text === null || text === undefined || text === '' ? '—' : String(text);
    if (className) td.className = className;
    row.append(td);
    return td;
};
const when = (value) => (value ? new Date(value).toLocaleString() : '');

const statusAction = (row, credential, action, label) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = action === 'revoke' ? 'btn btn-danger-ghost btn-sm' : 'btn btn-ghost btn-sm';
    button.textContent = label;
    button.addEventListener('click', async () => {
        const ok = await UI.confirm({
            title: `${label} ${credential.id}?`,
            message: action === 'revoke' ? 'A revoked credential stays revoked. Wallets and verifiers see it in the status list after the next push.' : 'Verifiers see the change in the status list after the next push.',
            confirmLabel: label,
            danger: action === 'revoke',
        });
        if (!ok) return;
        try {
            await UI.sendJson(`${walletUrl}/credentials/${encodeURIComponent(credential.id)}/${action}`);
            UI.toast(`${credential.id}: ${action === 'reinstate' ? 'valid again' : `${action}d`}`);
            loadRecords();
        } catch (error) {
            UI.toast(error.message, 'error');
        }
    });
    row.append(button);
};

async function loadRecords() {
    const body = document.querySelector('[data-records]');
    let result;
    try {
        const response = await fetch(`${walletUrl}/records`);
        if (!response.ok) throw new Error();
        result = await response.json();
    } catch {
        body.textContent = '';
        const row = document.createElement('tr');
        cell(row, 'The records could not be loaded.', 'muted').colSpan = 6;
        body.append(row);
        return;
    }
    const items = isIssuer ? result.credentials : result.verifications;
    body.textContent = '';
    if (!items.length) {
        const row = document.createElement('tr');
        cell(row, isIssuer ? 'No credentials issued yet.' : 'No verifications yet.', 'muted').colSpan = 6;
        body.append(row);
        return;
    }
    for (const item of items) {
        const row = document.createElement('tr');
        if (isIssuer) {
            cell(row, item.id, 'mono-sm');
            cell(row, item.credentialType);
            cell(row, item.subject);
            cell(row, item.status);
            cell(row, when(item.issuedAt));
            const actions = cell(row, '');
            actions.textContent = '';
            if (item.status === 'valid') {
                statusAction(actions, item, 'suspend', 'Suspend');
                statusAction(actions, item, 'revoke', 'Revoke');
            } else if (item.status === 'suspended') {
                statusAction(actions, item, 'reinstate', 'Reinstate');
                statusAction(actions, item, 'revoke', 'Revoke');
            }
        } else {
            cell(row, when(item.startedAt));
            cell(row, item.credentialType);
            cell(row, item.reason ? `${item.status} (${item.reason})` : item.status);
            cell(row, item.issuer);
            cell(row, (item.claimNames || []).join(', '));
            cell(row, item.callback);
        }
        body.append(row);
    }
}

document.querySelector('[data-records-refresh]')?.addEventListener('click', loadRecords);
loadRecords();
