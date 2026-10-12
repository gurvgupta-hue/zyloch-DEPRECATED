const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  extractDomain,
  isPublicEmailDomain,
  tenantDomainFromEmail,
} = require('../helpers/emailDomain');
const { schema: OrganizationSchema } = require('../models/schemas/control/organizationSchema');

describe('MT-07.1 email domain classification', () => {
  it('extracts and lowercases the domain', () => {
    assert.equal(extractDomain('  Alice@Acme.COM '), 'acme.com');
    assert.equal(extractDomain('a@b@corp.io'), 'corp.io');
  });

  it('returns null for malformed addresses', () => {
    for (const bad of ['', null, undefined, 'no-at-sign', 'trailing@', 'a@localhost']) {
      assert.equal(extractDomain(bad), null, `expected null for ${JSON.stringify(bad)}`);
    }
  });

  it('recognises consumer mailbox providers', () => {
    for (const d of ['gmail.com', 'GMAIL.COM', 'outlook.com', 'icloud.com', 'proton.me']) {
      assert.equal(isPublicEmailDomain(d), true, `${d} should be public`);
    }
  });

  it('treats GitHub no-reply addresses as non-identifying', () => {
    assert.equal(isPublicEmailDomain('users.noreply.github.com'), true);
    assert.equal(tenantDomainFromEmail('1234+bob@users.noreply.github.com'), null);
  });

  it('treats a corporate domain as claimable', () => {
    assert.equal(isPublicEmailDomain('acme.com'), false);
    assert.equal(tenantDomainFromEmail('alice@acme.com'), 'acme.com');
  });

  it('never claims a consumer domain', () => {
    // The original bug: the first gmail signup claimed "gmail.com" and every
    // later gmail signup then failed with a 409.
    assert.equal(tenantDomainFromEmail('alice@gmail.com'), null);
    assert.equal(tenantDomainFromEmail('bob@gmail.com'), null);
    assert.equal(tenantDomainFromEmail('carol@outlook.com'), null);
  });
});

describe('MT-07.1 organization domain index', () => {
  const domainIndex = OrganizationSchema.indexes().find(
    ([fields]) => Object.prototype.hasOwnProperty.call(fields, 'domain')
  );

  it('is NOT unique — two admins at one company are two tenants', () => {
    assert.ok(domainIndex, 'expected a domain index');
    const [, options = {}] = domainIndex;
    assert.notEqual(
      options.unique,
      true,
      'a unique domain index would push a second admin at the same company into ' +
        'the first admin\'s tenant, or lock them out entirely'
    );
  });

  it('allows a tenant with no domain and no admin', () => {
    const Organization = require('mongoose').model(
      `OrgDomainTest_${Date.now()}`,
      OrganizationSchema
    );
    const org = new Organization({
      name: 'Unclaimed Co',
      databaseName: 'zyloch_tenant_x',
    });
    const err = org.validateSync();
    assert.equal(err, undefined, `unexpected validation error: ${err?.message}`);
    assert.equal(org.domain, null);
    assert.equal(org.adminUserId, null);
  });

  it('isAdmin is safe when no admin has claimed the tenant yet', () => {
    const Organization = require('mongoose').model(
      `OrgAdminTest_${Date.now()}`,
      OrganizationSchema
    );
    const org = new Organization({ name: 'X', databaseName: 'zyloch_tenant_y' });
    assert.equal(org.isAdmin('674a1b2c3d4e5f6789012345'), false);
  });
});
