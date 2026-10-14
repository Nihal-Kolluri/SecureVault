const { Readable } = require('stream');

/**
 * In-memory S3/MinIO compatible storage client.
 * Implements the exact streaming interface of minio.Client (putObject, getObject, statObject, removeObject, bucketExists, makeBucket).
 * Used when an external MinIO server is not configured or for isolated, fast unit and integration tests.
 */
class MemoryStorageClient {
  constructor() {
    this.buckets = new Set();
    this.objects = new Map();
  }

  async bucketExists(bucketName) {
    return this.buckets.has(bucketName);
  }

  async makeBucket(bucketName) {
    this.buckets.add(bucketName);
  }

  async putObject(bucketName, objectName, stream, size, metaData = {}) {
    if (!this.buckets.has(bucketName)) {
      this.buckets.add(bucketName);
    }

    const chunks = [];
    if (Buffer.isBuffer(stream)) {
      chunks.push(stream);
    } else if (typeof stream === 'string') {
      chunks.push(Buffer.from(stream, 'utf8'));
    } else if (stream && typeof stream[Symbol.asyncIterator] === 'function') {
      for await (const chunk of stream) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
    } else if (stream && typeof stream.on === 'function') {
      await new Promise((resolve, reject) => {
        stream.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        stream.on('end', resolve);
        stream.on('error', reject);
      });
    }

    const buffer = Buffer.concat(chunks);
    const key = `${bucketName}/${objectName}`;
    this.objects.set(key, {
      buffer,
      metaData: { ...metaData },
      size: buffer.length,
      lastModified: new Date()
    });

    return { etag: `etag-${Date.now()}`, versionId: null };
  }

  async getObject(bucketName, objectName) {
    const key = `${bucketName}/${objectName}`;
    const obj = this.objects.get(key);
    if (!obj) {
      const err = new Error(`Object ${objectName} does not exist in bucket ${bucketName}`);
      err.code = 'NoSuchKey';
      throw err;
    }

    let offset = 0;
    const chunkSize = 64 * 1024; // 64KB chunks to simulate streaming chunks
    const buffer = obj.buffer;

    const readable = new Readable({
      read() {
        if (offset >= buffer.length) {
          this.push(null);
          return;
        }
        const nextOffset = Math.min(offset + chunkSize, buffer.length);
        const chunk = buffer.subarray(offset, nextOffset);
        offset = nextOffset;
        this.push(chunk);
      }
    });

    return readable;
  }

  async statObject(bucketName, objectName) {
    const key = `${bucketName}/${objectName}`;
    const obj = this.objects.get(key);
    if (!obj) {
      const err = new Error(`Object ${objectName} does not exist in bucket ${bucketName}`);
      err.code = 'NoSuchKey';
      throw err;
    }
    return {
      size: obj.size,
      metaData: obj.metaData,
      lastModified: obj.lastModified
    };
  }

  async removeObject(bucketName, objectName) {
    const key = `${bucketName}/${objectName}`;
    this.objects.delete(key);
  }

  /**
   * Tamper inspection helper for security tests
   */
  _getRawBuffer(bucketName, objectName) {
    const key = `${bucketName}/${objectName}`;
    return this.objects.get(key)?.buffer;
  }

  _setRawBuffer(bucketName, objectName, newBuffer) {
    const key = `${bucketName}/${objectName}`;
    const obj = this.objects.get(key);
    if (obj) {
      obj.buffer = newBuffer;
      obj.size = newBuffer.length;
    }
  }

  _clear() {
    this.objects.clear();
    this.buckets.clear();
  }
}

module.exports = {
  MemoryStorageClient
};
