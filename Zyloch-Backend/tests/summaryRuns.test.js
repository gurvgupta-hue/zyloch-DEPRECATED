const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const { findLiveRun, reportProgress } = require('../services/summaryRuns');

const TENANT_A = '674a1b2c3d4e5f6789012345';
const INSTALL_ID = 424242;

const fakeQueue = (jobs) => ({
  getJob: async (id) => {
    const entry = jobs[id];
    if (!entry) return null;
    return { id, data: entry.data || {}, getState: async () => entry.state };
  },
});

describe('findLiveRun', () => {
  for (const state of ['waiting', 'prioritized', 'delayed', 'active', 'waiting-children']) {
    it(`treats a "${state}" job as live`, async () => {
      const run = await findLiveRun(fakeQueue({ b1: { state } }), { bullmqJobId: 'b1' });
      assert.equal(run.state, state);
      assert.equal(run.bullJob.id, 'b1');
    });
  }

  for (const state of ['completed', 'failed', 'unknown']) {
    it(`treats a "${state}" job as finished`, async () => {
      assert.equal(await findLiveRun(fakeQueue({ b1: { state } }), { bullmqJobId: 'b1' }), null);
    });
  }

  it('is null when the job is gone, never queued, or the lookup fails', async () => {
    assert.equal(await findLiveRun(fakeQueue({}), { bullmqJobId: 'gone' }), null);
    assert.equal(await findLiveRun(fakeQueue({}), { bullmqJobId: null }), null);
    assert.equal(await findLiveRun(fakeQueue({}), null), null);
    const broken = { getJob: async () => { throw new Error('redis down'); } };
    assert.equal(await findLiveRun(broken, { bullmqJobId: 'b1' }), null);
    // Test doubles of the queue that only implement add().
    assert.equal(await findLiveRun({ add: async () => ({}) }, { bullmqJobId: 'b1' }), null);
  });
});

describe('reportProgress', () => {
  function capture() {
    const calls = [];
    return {
      calls,
      Model: { updateOne: async (filter, update) => { calls.push({ filter, update }); } },
    };
  }

  it('only moves forward, and only for the run that owns the document', async () => {
    const { calls, Model } = capture();
    const bullProgress = [];
    const job = { id: 'b7', updateProgress: async (p) => bullProgress.push(p) };

    await reportProgress(job, Model, 'doc-1', 57);

    assert.deepEqual(bullProgress, [57]);
    assert.deepEqual(calls[0].filter, {
      _id: 'doc-1',
      progress: { $lt: 57 },
      $or: [{ bullmqJobId: 'b7' }, { bullmqJobId: null }],
    });
    assert.deepEqual(calls[0].update, { $set: { progress: 57 } });
  });

  it('clamps to 0–100 and still writes when BullMQ rejects its own copy', async () => {
    const { calls, Model } = capture();
    const job = { id: 1, updateProgress: async () => { throw new Error('lock lost'); } };

    await reportProgress(job, Model, 'doc-1', 140.7);
    await reportProgress(job, Model, 'doc-1', -3);

    assert.equal(calls[0].update.$set.progress, 100);
    assert.equal(calls[1].update.$set.progress, 0);
    assert.deepEqual(calls[0].filter.$or[0], { bullmqJobId: '1' });
  });
});

// Every way into a sync used to queue another BullMQ job unconditionally; with a
// worker concurrency of 5 the runs raced on one progress field.
describe('summary entry points join a running sync', () => {
  const path = require('path');
  const controllerPath = path.resolve(__dirname, '../controllers/installationSummaryController.js');
  const summaryQueuePath = path.resolve(__dirname, '../queues/summaryQueue.js');
  const installation = { installationId: INSTALL_ID, account: { id: 42, login: 'acme', type: 'Organization' } };

  let controller;
  let tenantScope;
  let originalAssert;
  let queued;
  let bullJobs;

  beforeEach(() => {
    queued = [];
    bullJobs = {};
    require.cache[summaryQueuePath] = {
      id: summaryQueuePath,
      filename: summaryQueuePath,
      loaded: true,
      exports: {
        ...fakeQueue(bullJobs),
        add: async (name, data, opts) => {
          queued.push({ name, data, opts });
          return { id: `bull-${queued.length}` };
        },
      },
    };
    tenantScope = require('../helpers/tenantScope');
    originalAssert = tenantScope.assertInstallationBelongsToTenant;
    tenantScope.assertInstallationBelongsToTenant = async () => installation;
    delete require.cache[controllerPath];
    controller = require('../controllers/installationSummaryController');
  });

  afterEach(() => {
    tenantScope.assertInstallationBelongsToTenant = originalAssert;
    delete require.cache[summaryQueuePath];
    delete require.cache[controllerPath];
  });

  function request(summaryJob, query = {}) {
    const writes = [];
    const req = {
      params: { installationId: String(INSTALL_ID) },
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      user: { login: 'admin' },
      query,
      models: {
        InstallationSummaryJob: {
          findOne: async () => summaryJob,
          findOneAndUpdate: async (filter, update) => {
            writes.push(update);
            return { ...summaryJob, _id: summaryJob?._id || 'job-1', ...update.$set };
          },
          findByIdAndUpdate: async (id, update) => {
            writes.push(update);
            return { ...summaryJob, _id: id, ...(update.$set || update) };
          },
        },
      },
    };
    return { req, writes };
  }

  async function call(handler, req) {
    let body;
    let error;
    await controller[handler](req, { json: (data) => { body = data; } }, (err) => { error = err; });
    if (error) throw error;
    return body;
  }

  for (const [handler, query] of [
    ['startSummaryJob', {}],
    ['startSummaryJob', { forceRefresh: 'true' }],
    ['refreshInstallationData', {}],
    ['refreshInstallationData', { forceRefresh: 'true' }],
  ]) {
    it(`${handler}${query.forceRefresh ? ' (force)' : ''} returns the running job without queueing or resetting it`, async () => {
      bullJobs['bull-live'] = { state: 'active' };
      const { req, writes } = request(
        { _id: 'job-1', status: 'in_progress', progress: 63, bullmqJobId: 'bull-live' },
        query
      );

      const body = await call(handler, req);

      assert.equal(body.alreadyRunning, true);
      assert.equal(String(body.jobId), 'job-1');
      assert.equal(body.bullmqJobId, 'bull-live');
      assert.deepEqual(queued, [], 'no second BullMQ job');
      assert.deepEqual(writes, [], 'the running job document is left untouched');
    });
  }

  it('startSummaryJob restarts a dead run from zero instead of inheriting its progress', async () => {
    bullJobs['bull-dead'] = { state: 'failed' };
    const { req, writes } = request({
      _id: 'job-1',
      status: 'in_progress',
      progress: 63,
      bullmqJobId: 'bull-dead',
    });

    const body = await call('startSummaryJob', req);

    assert.equal(body.status, 'processing_started');
    assert.equal(queued.length, 1);
    assert.ok(
      writes.some((w) => w.$set?.status === 'pending' && w.$set?.progress === 0),
      'progress reset before the new run is queued'
    );
  });

  it('startSummaryJob still serves a finished summary from cache', async () => {
    const { req } = request({ _id: 'job-1', status: 'completed', summary: { totals: {} }, bullmqJobId: 'old' });

    const body = await call('startSummaryJob', req);

    assert.equal(body.status, 'from_cache');
    assert.deepEqual(queued, []);
  });
});
