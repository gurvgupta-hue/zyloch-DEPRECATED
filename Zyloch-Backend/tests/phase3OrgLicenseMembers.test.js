const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

describe('KAN-46 organization domain index', () => {
  it('Organization schema declares a NON-unique domain index', () => {
    // A domain is a label, not an identity. Two admins at the same company are
    // two separate organizations, so uniqueness here would either merge them or
    // lock the second one out at signup.
    const { schema } = require('../models/schemas/control/organizationSchema');
    const indexes = schema.indexes();
    const domainIndex = indexes.find(([fields]) => fields.domain === 1);
    assert.ok(domainIndex, 'expected a domain index for support lookups');
    assert.notEqual(domainIndex[1]?.unique, true, 'domain index must not be unique');
  });
});

describe('KAN-49 auth identity multi-tenant index', () => {
  it('AuthIdentity unique key includes tenantId', () => {
    const { schema } = require('../models/schemas/control/authIdentitySchema');
    const indexes = schema.indexes();
    const compound = indexes.some(
      ([fields, options]) =>
        fields.provider === 1 &&
        fields.providerId === 1 &&
        fields.tenantId === 1 &&
        options &&
        options.unique === true
    );
    assert.equal(compound, true);
  });
});

describe('KAN-45 member invite schema', () => {
  it('MemberInvite has tenantId and pending status', () => {
    const { schema } = require('../models/schemas/memberInviteSchema');
    assert.ok(schema.path('tenantId'));
    assert.ok(schema.path('email'));
    assert.ok(schema.path('token'));
    assert.equal(schema.path('status').enumValues.includes('pending'), true);
  });
});
