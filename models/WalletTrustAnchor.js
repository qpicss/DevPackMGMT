const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

// A trust anchor of a wallet gateway: CA certificates (PEM) that the chains of credential issuers
// or Wallet Providers must lead to. Grouped by entitlement (PID, QEAA, PuB-EAA, EAA, WalletProvider).
const WalletTrustAnchor = sequelize.define('WalletTrustAnchor', {
  id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
  organizationId: { type: DataTypes.UUID, allowNull: false },
  gatewayId: { type: DataTypes.UUID, allowNull: false },
  name: { type: DataTypes.STRING, allowNull: false },
  entitlement: { type: DataTypes.STRING(20), allowNull: false, defaultValue: 'EAA' },
  certificatesPem: { type: DataTypes.TEXT, allowNull: false },
}, { timestamps: true });

module.exports = WalletTrustAnchor;
