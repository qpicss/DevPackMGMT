UI.bindForm(document.getElementById('gatewayForm'), {
    alert: document.getElementById('gateway-alert'),
    loadingLabel: 'Creating…',
    submit: async (formData) => {
        const result = await UI.sendJson('/api/org/gateways', {
            body: {
                name: formData.get('name'),
                publicUrl: formData.get('publicUrl'),
                kind: formData.get('kind'),
            },
        });
        UI.flash(result.gateway.kind === 'api'
            ? `${result.gateway.name} was created. Add a port, then start a node with its credentials.`
            : `${result.gateway.name} was created. Add the client's certificates on its Wallet page, then a port and a node.`);
        window.location.href = `/developer/gateways/${encodeURIComponent(result.gateway.id)}`;
    },
});

