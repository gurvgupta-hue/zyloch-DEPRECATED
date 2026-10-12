const mongoose = require('mongoose');

/** Platform-global YARA rule catalog (shared across all tenants). */
const YaraRuleSchema = new mongoose.Schema(
  {
    rulename: { type: String, required: true, unique: true },
    content: { type: String, required: true },
    meta: { type: mongoose.Schema.Types.Mixed, default: {} },
    tags: { type: [String], default: [] },
    enabled: { type: Boolean, default: true },
  },
  { timestamps: { createdAt: true, updatedAt: false }, collection: 'yara_rules' }
);

module.exports = { schema: YaraRuleSchema, modelName: 'YaraRule', collection: 'yara_rules' };
