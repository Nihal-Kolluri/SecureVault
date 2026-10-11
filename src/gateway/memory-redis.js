/**
 * In-memory Redis adapter implementing the exact Redis primitives needed for rate limiting.
 * Used when an external Redis server is not available or for fast, reliable unit testing.
 */
class MemoryRedis {
  constructor() {
    this.store = new Map();
    this.ttls = new Map();
  }

  _isExpired(key) {
    if (!this.ttls.has(key)) return false;
    const expiresAt = this.ttls.get(key);
    if (Date.now() >= expiresAt) {
      this.store.delete(key);
      this.ttls.delete(key);
      return true;
    }
    return false;
  }

  async incr(key) {
    if (this._isExpired(key)) {
      this.store.delete(key);
      this.ttls.delete(key);
    }
    const current = Number(this.store.get(key) || 0);
    const next = current + 1;
    this.store.set(key, String(next));
    return next;
  }

  async get(key) {
    if (this._isExpired(key)) return null;
    return this.store.get(key) || null;
  }

  async set(key, value) {
    this.store.set(key, String(value));
    return 'OK';
  }

  async pexpire(key, milliseconds) {
    if (!this.store.has(key) || this._isExpired(key)) return 0;
    this.ttls.set(key, Date.now() + Number(milliseconds));
    return 1;
  }

  async expire(key, seconds) {
    return this.pexpire(key, Number(seconds) * 1000);
  }

  async pttl(key) {
    if (!this.store.has(key) || this._isExpired(key)) return -2;
    if (!this.ttls.has(key)) return -1;
    const remaining = this.ttls.get(key) - Date.now();
    return remaining > 0 ? remaining : -2;
  }

  async ttl(key) {
    const ms = await this.pttl(key);
    if (ms < 0) return ms;
    return Math.ceil(ms / 1000);
  }

  async del(key) {
    const existed = this.store.has(key);
    this.store.delete(key);
    this.ttls.delete(key);
    return existed ? 1 : 0;
  }

  async flushall() {
    this.store.clear();
    this.ttls.clear();
    return 'OK';
  }

  async disconnect() {
    this.store.clear();
    this.ttls.clear();
  }
}

module.exports = {
  MemoryRedis
};
