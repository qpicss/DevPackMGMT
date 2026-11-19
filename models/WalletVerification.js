const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

// A verification a wallet verifier gateway ran: metadata only (claim names, never values).
const WalletVerification = sequelize.define('WalletVerification', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  organizationId: { type: DataTypes.UUID, allowNull: false },
  gatewayId: { type: DataTypes.UUID, allowNull: false },
  sessionId: { type: DataTypes.STRING(64), allowNull: false },
  clientId: { type: DataTypes.STRING(255) },
  credentialType: { type: DataTypes.STRING(64) },
  status: { type: DataTypes.STRING(20), allowNull: false, defaultValue: 'pending' },
  reason: { type: DataTypes.STRING(64) },
  issuer: { type: DataTypes.STRING(500) },
  reference: { type: DataTypes.STRING(200) },
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
  // Delivery of the result to the provider server: delivered | failed.
  callback: { type: DataTypes.STRING(20) },
  startedAt: { type: DataTypes.DATE },
  completedAt: { type: DataTypes.DATE },
}, {
  timestamps: true,
  indexes: [{ unique: true, fields: ['gatewayId', 'sessionId'] }],
});

module.exports = WalletVerification;
