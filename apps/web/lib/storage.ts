import crypto from "crypto";

export interface StorageUploadOptions {
  contentType: string;
  filename: string;
}

export interface StoredObject {
  url: string;
  key: string;
}

export interface StorageDriver {
  upload(buffer: Buffer, options: StorageUploadOptions): Promise<StoredObject>;
}

class InMemoryStorage implements StorageDriver {
  private files = new Map<string, Buffer>();

  async upload(buffer: Buffer, options: StorageUploadOptions): Promise<StoredObject> {
    const key = `${Date.now()}-${crypto.randomUUID()}-${options.filename}`;
    this.files.set(key, buffer);
    return {
      key,
      url: `memory://${key}`
    };
  }
}

let driver: StorageDriver | null = null;

export function getStorageDriver(): StorageDriver {
  if (!driver) {
    driver = new InMemoryStorage();
  }
  return driver;
}
