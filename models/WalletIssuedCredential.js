const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

// A credential a wallet issuer gateway issued: metadata only (claim names, never values). Its
// status (valid, suspended, revoked) is published in the gateway's status list at `statusIndex`.
const WalletIssuedCredential = sequelize.define('WalletIssuedCredential', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  organizationId: { type: DataTypes.UUID, allowNull: false },
  gatewayId: { type: DataTypes.UUID, allowNull: false },
  // "<list id>-<status index>", as the gateway and the provider server know it.
  credentialId: { type: DataTypes.STRING(64), allowNull: false },
  offerId: { type: DataTypes.STRING(64) },
  clientId: { type: DataTypes.STRING(255) },
  credentialType: { type: DataTypes.STRING(64) },
  subject: { type: DataTypes.STRING(200) },
  listId: { type: DataTypes.STRING(40), allowNull: false },
  statusIndex: { type: DataTypes.INTEGER, allowNull: false },
  node: { type: DataTypes.STRING(255) },
  status: { type: DataTypes.STRING(20), allowNull: false, defaultValue: 'valid' },
  claimNames: {
    type: DataTypes.TEXT,
    get() {
      const raw = this.getDataValue('claimNames');
      return raw ? JSON.parse(raw) : [];
    },
    set(value) {
      this.setDataValue('claimNames', JSON.stringify(value || []));
    },
  },
  issuedAt: { type: DataTypes.DATE },
  expiresAt: { type: DataTypes.DATE },
}, {
  timestamps: true,
  indexes: [{ unique: true, fields: ['gatewayId', 'credentialId'] }],
});

module.exports = WalletIssuedCredential;
