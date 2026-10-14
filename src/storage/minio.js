const Minio = require('minio');
const { MemoryStorageClient } = require('./memory-storage');

let storageClientInstance = null;
let bucketInitialized = false;

/**
 * Returns the configured default bucket name.
 * @returns {string}
 */
function getBucketName() {
  return process.env.MINIO_BUCKET || 'securevault-files';
}

/**
 * Gets or initializes the storage client (MinIO or MemoryStorageClient fallback).
 * @returns {Minio.Client|MemoryStorageClient}
 */
function getStorageClient() {
  if (storageClientInstance) {
    return storageClientInstance;
  }

  // If memory client is explicitly requested or running in test without minio host
  if (process.env.STORAGE_TYPE === 'memory' || process.env.NODE_ENV === 'test') {
    storageClientInstance = new MemoryStorageClient();
    return storageClientInstance;
  }

  const endpoint = process.env.MINIO_ENDPOINT || 'localhost';
  const port = parseInt(process.env.MINIO_PORT || '9000', 10);
  const useSSL = process.env.MINIO_USE_SSL === 'true';
  const accessKey = process.env.MINIO_ACCESS_KEY || 'minioadmin';
  const secretKey = process.env.MINIO_SECRET_KEY || 'minioadmin';

  try {
    const client = new Minio.Client({
      endPoint: endpoint,
      port,
      useSSL,
      accessKey,
      secretKey
    });
    storageClientInstance = client;
    return storageClientInstance;
  } catch (error) {
    // Fall back to MemoryStorageClient if Minio initialization fails
    storageClientInstance = new MemoryStorageClient();
    return storageClientInstance;
  }
}

/**
 * Overrides the storage client instance (useful in tests).
 * @param {object|null} client
 */
function setStorageClient(client) {
  storageClientInstance = client;
  bucketInitialized = false;
}

/**
 * Resets the storage client instance.
 */
function resetStorageClient() {
  storageClientInstance = null;
  bucketInitialized = false;
}

/**
 * Ensures that the target storage bucket exists.
 * @param {string} [bucketName]
 */
async function ensureBucket(bucketName = getBucketName()) {
  const client = getStorageClient();
  try {
    const exists = await client.bucketExists(bucketName);
    if (!exists) {
      await client.makeBucket(bucketName, 'us-east-1');
    }
    bucketInitialized = true;
  } catch (error) {
    // If bucket already owned or exists, consider initialized
    if (error.code === 'BucketAlreadyOwnedByYou' || error.code === 'BucketAlreadyExists') {
      bucketInitialized = true;
      return;
    }
    throw error;
  }
}

/**
 * Uploads a readable stream to MinIO/S3 object storage.
 * @param {string} bucket
 * @param {string} objectKey
 * @param {import('stream').Readable} stream
 * @param {number} [size]
 * @param {object} [metadata]
 * @returns {Promise<object>}
 */
async function putObjectStream(bucket, objectKey, stream, size, metadata = {}) {
  const client = getStorageClient();
  await ensureBucket(bucket);
  return await client.putObject(bucket, objectKey, stream, size, metadata);
}

/**
 * Retrieves an object as a readable stream from MinIO/S3 object storage.
 * @param {string} bucket
 * @param {string} objectKey
 * @returns {Promise<import('stream').Readable>}
 */
async function getObjectStream(bucket, objectKey) {
  const client = getStorageClient();
  return await client.getObject(bucket, objectKey);
}

/**
 * Deletes an object from MinIO/S3 storage.
 * @param {string} bucket
 * @param {string} objectKey
 * @returns {Promise<void>}
 */
async function deleteObject(bucket, objectKey) {
  const client = getStorageClient();
  return await client.removeObject(bucket, objectKey);
}

/**
 * Retrieves metadata/stat of an object.
 * @param {string} bucket
 * @param {string} objectKey
 * @returns {Promise<object>}
 */
async function statObject(bucket, objectKey) {
  const client = getStorageClient();
  return await client.statObject(bucket, objectKey);
}

module.exports = {
  getStorageClient,
  setStorageClient,
  resetStorageClient,
  getBucketName,
  ensureBucket,
  putObjectStream,
  getObjectStream,
  deleteObject,
  statObject
};
