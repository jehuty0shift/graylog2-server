class PluginManifest {
  constructor(metadata, exports) {
    this.metadata = metadata;
    this.exports = exports;
  }

  static create(metadata, exports) {
    return new PluginManifest(metadata, exports);
  }
}

module.exports = PluginManifest;
