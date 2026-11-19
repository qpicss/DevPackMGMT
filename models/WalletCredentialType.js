const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const json = (name, fallback) => ({
  type: DataTypes.TEXT,
  get() {
    const raw = this.getDataValue(name);
    return raw ? JSON.parse(raw) : fallback;
  },
  set(value) {
    this.setDataValue(name, JSON.stringify(value === undefined ? fallback : value));
  },
});

// A credential type a wallet gateway verifies or issues (SD-JWT VC): its vct, its claims (paths)
// and, for verifiers, the trust anchors its issuers must chain to.
const WalletCredentialType = sequelize.define('WalletCredentialType', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  organizationId: { type: DataTypes.UUID, allowNull: false },
  gatewayId: { type: DataTypes.UUID, allowNull: false },
  // The identifier callers and wallets use, e.g. "diploma" (the credential_configuration_id for issuers).
  key: { type: DataTypes.STRING(64), allowNull: false },
  name: { type: DataTypes.STRING, allowNull: false },
  vct: { type: DataTypes.STRING(500), allowNull: false },
  claims: json('claims', []),
  anchorIds: json('anchorIds', []),
  display: json('display', null),
  validityDays: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 365 },
  requireIssuerName: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
}, { timestamps: true });

module.exports = WalletCredentialType;
