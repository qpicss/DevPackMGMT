// Short-lived wallet state (verification sessions, offers, codes, nonces): in Redis when the node
// has REDIS_URL (needed when several nodes serve one gateway), otherwise in this process.
// Values are JSON; every entry expires.

class MemorySessions {
  constructor() {
    this.entries = new Map();
    this.timer = setInterval(() => this.sweep(), 60000);
    this.timer.unref?.();
    this.mode = 'memory';
  }

  sweep(now = Date.now()) {
    for (const [key, entry] of this.entries) if (entry.until <= now) this.entries.delete(key);
  }

  async get(key) {
    const entry = this.entries.get(key);
    if (!entry || entry.until <= Date.now()) return null;
    return JSON.parse(entry.value);
  }

  async set(key, value, ttlSeconds) {
    if (this.entries.size > 200000) this.sweep();
    this.entries.set(key, { value: JSON.stringify(value), until: Date.now() + ttlSeconds * 1000 });
  }

  // Reads and removes in one step, for values that may be used only once.
  async take(key) {
    const value = await this.get(key);
    this.entries.delete(key);
    return value;
  }

  async del(key) {
    this.entries.delete(key);
  }

  async close() {
    clearInterval(this.timer);
  }
}

class RedisSessions {
  constructor({ redisUrl, gatewayId, logger }) {
    const { createClient } = require('redis');
    this.prefix = `wallet:${gatewayId}:`;
    this.client = createClient({ url: redisUrl, socket: { reconnectStrategy: (retries) => Math.min(retries * 200, 5000) } });
    this.client.on('error', (error) => logger.warn('wallet session store error', { error: error.message }));
    this.ready = this.client.connect().catch((error) => logger.error('wallet session store unavailable', { error: error.message }));
    this.mode = 'redis';
  }

  async get(key) {
    await this.ready;
    const value = await this.client.get(this.prefix + key);
    return value ? JSON.parse(value) : null;
  }

  async set(key, value, ttlSeconds) {
    await this.ready;
    await this.client.set(this.prefix + key, JSON.stringify(value), { EX: Math.max(1, Math.ceil(ttlSeconds)) });
  }

  async take(key) {
    await this.ready;
    const value = await this.client.getDel(this.prefix + key);
    return value ? JSON.parse(value) : null;
  }

  async del(key) {
    await this.ready;
    await this.client.del(this.prefix + key);
  }

  async close() {
    await this.client.quit().catch(() => {});
  }
}

const createSessionStore = ({ redisUrl, gatewayId, logger }) => (redisUrl ? new RedisSessions({ redisUrl, gatewayId, logger }) : new MemorySessions());

module.exports = { createSessionStore, MemorySessions };
