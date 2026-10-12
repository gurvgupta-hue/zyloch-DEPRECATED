const createError = require("../utils/createError");
const summaryQueue = require("../queues/summaryQueue");
const { validatePositiveInteger } = require("../utils/validation");
const tenantScope = require("../helpers/tenantScope");
const { findLiveRun } = require("../services/summaryRuns");

async function assertJobInstallationScope(req, installationId) {
  return tenantScope.assertInstallationBelongsToTenant(installationId, req.tenant.id);
}

async function startSummaryJob(req, res, next) {
  try {
    let installationId;
    try {
      installationId = validatePositiveInteger(req.params.installationId, "installationId");
    } catch (err) {
      return next(err);
    }

    const { InstallationSummaryJob } = req.models;
    const tenantId = req.tenantId;
    const { login } = req.user || {};
    const forceRefresh = req.query.forceRefresh === "true";

    if (!login) return next(createError(401, "Unauthorized"));
    if (!installationId) return next(createError(400, "Invalid installation ID"));

    const installation = await assertJobInstallationScope(req, installationId);

    // A run already queued or working for this installation is joined, not
    // duplicated: a second run would race the first on the same progress field.
    // This runs before the upsert below, which would otherwise reset progress.
    const jobFilter = { tenantId, installationId, accountId: installation.account.id };
    const existingJob = await InstallationSummaryJob.findOne(jobFilter);
    const liveRun = await findLiveRun(summaryQueue, existingJob);
    if (liveRun) {
      return res.json({
        status: "processing_started",
        jobId: existingJob._id,
        bullmqJobId: liveRun.bullJob.id,
        alreadyRunning: true,
      });
    }

    // A field may be written by only one update operator. Naming it in both
    // `$setOnInsert` and `$set` makes MongoDB reject the whole update with
    // "Updating the path 'x' would create a conflict at 'x'". `tenantId` never
    // changes and is already in the filter, so it belongs to `$setOnInsert`
    // alone; the account fields move to `$set` only on a forced refresh, which
    // is the one case that rewrites them on an existing job.
    const now = new Date();
    const setOnInsert = { tenantId, installationId, createdAt: now };
    const set = { updatedAt: now };

    const accountFields = {
      login: installation.account.login,
      accountId: installation.account.id,
      accountType: installation.account.type,
    };

    if (forceRefresh) {
      Object.assign(set, accountFields, {
        status: "pending",
        progress: 0,
        error: null,
        summary: undefined,
      });
    } else {
      Object.assign(setOnInsert, accountFields, { status: "pending", progress: 0 });
    }

    let job = await InstallationSummaryJob.findOneAndUpdate(
      jobFilter,
      { $setOnInsert: setOnInsert, $set: set },
      { upsert: true, new: true }
    );

    if (job.status === "completed" && job.summary && !forceRefresh) {
      return res.json({
        status: "from_cache",
        jobId: job._id,
        summary: normalizeSummary(job.summary),
        updatedAt: job.updatedAt,
      });
    }

    // Not live and not finished: the previous run died (worker restart, lost
    // lock). Its partial progress would hold the new run's bar still until it
    // caught up, so the new run starts visibly from zero.
    if (!forceRefresh && job.status !== "pending") {
      job = await InstallationSummaryJob.findByIdAndUpdate(
        job._id,
        { $set: { status: "pending", progress: 0, error: null } },
        { new: true }
      );
    }

    const bullJob = await summaryQueue.add('process-installation', {
      tenantId,
      installationId,
      login: installation.account.login,
      accountId: installation.account.id,
      accountType: installation.account.type,
      mongoJobId: job._id,
      forceRefresh,
    }, {
      jobId: `install-${installationId}-${Date.now()}`,
      priority: forceRefresh ? 1 : 10,
    });

    await InstallationSummaryJob.findByIdAndUpdate(job._id, {
      bullmqJobId: bullJob.id,
    });


    res.json({
      status: "processing_started",
      jobId: job._id,
      bullmqJobId: bullJob.id,
    });
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, err.message));
  }
}

async function getJobStatus(req, res, next) {
  try {
    const { InstallationSummaryJob } = req.models;
    const job = await InstallationSummaryJob.findOne({
      _id: req.params.jobId,
      tenantId: req.tenantId,
    });
    if (!job) return next(createError(404, "Job not found"));

    await assertJobInstallationScope(req, job.installationId);

    let queueInfo = null;
    if (job.bullmqJobId) {
      try {
        const bullJob = await summaryQueue.getJob(job.bullmqJobId);
        if (bullJob) {
          queueInfo = {
            state: await bullJob.getState(),
            progress: bullJob.progress,
            attemptsMade: bullJob.attemptsMade,
            processedOn: bullJob.processedOn,
            finishedOn: bullJob.finishedOn,
          };
        }
      } catch (err) {
        console.error('Error fetching BullMQ job:', err.message);
      }
    }

    // `progress`, the repository count and the timestamps are what the sync
    // screen turns into "1,240 of 21,430 repositories · about 6 hours left".
    // Without them the UI can only spin, which is what it did before.
    const installation = await req.models.Installation.findOne({
      installationId: job.installationId,
    })
      .select('repoCount repos selectedRepos repoLimit')
      .lean();

    const targetRepoCount =
      (installation?.selectedRepos || []).length ||
      Number(installation?.repoCount) ||
      (installation?.repos || []).length ||
      job.summary?.totals?.totalRepositories ||
      0;

    res.json({
      status: job.status,
      progress: Number(job.progress) || 0,
      error: job.error,
      summary:
        job.status === "completed"
          ? normalizeSummary(job.summary)
          : normalizeSummary(),
      queueInfo,
      installationId: job.installationId,
      startedAt: job.createdAt || null,
      updatedAt: job.updatedAt || null,
      repositories: {
        target: targetRepoCount,
        processed: job.summary?.totals?.totalRepositories || 0,
      },
    });
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, err.message));
  }
}

async function retryFailedJob(req, res, next) {
  try {
    const { InstallationSummaryJob } = req.models;
    const tenantId = req.tenantId;
    const { jobId } = req.params;
    const { login } = req.user || {};

    if (!login) return next(createError(401, "Unauthorized"));
    if (!jobId) return next(createError(400, "Job ID is required"));

    // Find the MongoDB job record scoped to the caller's tenant
    const mongoJob = await InstallationSummaryJob.findOne({ _id: jobId, tenantId });
    if (!mongoJob) {
      return next(createError(404, "Job not found"));
    }

    await assertJobInstallationScope(req, mongoJob.installationId);

    // Verify the job belongs to the user
    if (mongoJob.login !== login) {
      return next(createError(403, "Forbidden: You don't own this job"));
    }

    let bullJob = null;
    let jobState = null;

    // Check if BullMQ job exists
    if (mongoJob.bullmqJobId) {
      bullJob = await summaryQueue.getJob(mongoJob.bullmqJobId);
      if (bullJob) {
        jobState = await bullJob.getState();
      }
    }

    console.log(`[RetryJob] Job ${jobId}, State: ${jobState}, BullMQ ID: ${mongoJob.bullmqJobId}`);

    // Only allow retry for failed jobs
    if (jobState === 'completed') {
      return res.json({
        success: false,
        message: "Job has already completed successfully",
        jobId: mongoJob._id,
      });
    }

    // Every unfinished BullMQ state, not only active/waiting: a queued job with a
    // priority reports `prioritized`, and retrying it would start a second run.
    const liveRun = await findLiveRun(summaryQueue, mongoJob);
    if (liveRun) {
      jobState = liveRun.state;
      return res.json({
        success: false,
        message: `Job is currently ${jobState}`,
        jobId: mongoJob._id,
      });
    }

    // Retry the BullMQ job if it exists and is in failed state
    if (bullJob && jobState === 'failed') {
      console.log(`[RetryJob] Retrying existing BullMQ job ${mongoJob.bullmqJobId}`);
      
      try {
        // Instead of retrying, let's create a fresh job
        // The retry() method sometimes doesn't trigger worker properly
        console.log(`[RetryJob] Removing failed job and creating new one`);
        
        // Remove the old failed job
        await bullJob.remove();
        
        // Create a new job
        const newBullJob = await summaryQueue.add('process-installation', {
          tenantId,
          installationId: mongoJob.installationId,
          login: mongoJob.login,
          accountId: mongoJob.accountId,
          accountType: mongoJob.accountType,
          mongoJobId: mongoJob._id,
          forceRefresh: true,
        }, {
          jobId: `install-${mongoJob.installationId}-${Date.now()}`,
          priority: 1, // High priority for retries
        });
        
        console.log(` [RetryJob] New job created: ${newBullJob.id}`);
        
        // Update MongoDB job with new BullMQ job ID
        await InstallationSummaryJob.findByIdAndUpdate(jobId, {
          bullmqJobId: newBullJob.id,
          status: "pending",
          progress: 0,
          error: null,
          updatedAt: new Date(),
        });

        return res.json({
          success: true,
          message: "Job retry initiated with new job",
          jobId: mongoJob._id,
          bullmqJobId: newBullJob.id,
        });
      } catch (retryError) {
        console.error(`? [RetryJob] Error during retry:`, retryError.message);
        throw retryError;
      }
    }

    // If no BullMQ job exists or it's not found, create a new one
    console.log(`[RetryJob] Creating new BullMQ job for installation ${mongoJob.installationId}`);
    
    const newBullJob = await summaryQueue.add('process-installation', {
      tenantId,
      installationId: mongoJob.installationId,
      login: mongoJob.login,
      accountId: mongoJob.accountId,
      accountType: mongoJob.accountType,
      mongoJobId: mongoJob._id,
      forceRefresh: true,
    }, {
      jobId: `install-${mongoJob.installationId}-${Date.now()}`,
      priority: 1, // High priority for retries
    });

    // Update MongoDB job with new BullMQ job ID
    await InstallationSummaryJob.findByIdAndUpdate(jobId, {
      bullmqJobId: newBullJob.id,
      status: "pending",
      progress: 0,
      error: null,
      updatedAt: new Date(),
    });

    res.json({
      success: true,
      message: "New job created for retry",
      jobId: mongoJob._id,
      bullmqJobId: newBullJob.id,
    });

  } catch (err) {
    console.error('? [RetryJob] Error:', err.message);
    if (err.statusCode) return next(err);
    next(createError(500, `Failed to retry job: ${err.message}`));
  }
}

async function refreshInstallationData(req, res, next) {
  try {
    const { InstallationSummaryJob } = req.models;
    const tenantId = req.tenantId;
    const installationId = +req.params.installationId;
    const { login } = req.user || {};
    const forceRefresh = req.query.forceRefresh === "true";

    if (!login) return next(createError(401, "Unauthorized"));
    if (!installationId) return next(createError(400, "Invalid installation ID"));

    const installation = await assertJobInstallationScope(req, installationId);

    // Check if installation has lastFetchedAt to determine if incremental is possible
    // Force refresh always does a full refresh regardless of lastFetchedAt
    const isIncremental = forceRefresh ? false : !!installation.lastFetchedAt;

    // Joined, not duplicated, while a run is in flight — and checked before the
    // upsert below, which resets progress to 0 mid-sync.
    const jobFilter = { tenantId, installationId, accountId: installation.account.id };
    const existingJob = await InstallationSummaryJob.findOne(jobFilter);
    const liveRun = await findLiveRun(summaryQueue, existingJob);
    if (liveRun) {
      return res.json({
        status: "refresh_started",
        jobId: existingJob._id,
        bullmqJobId: liveRun.bullJob.id,
        isIncremental: Boolean(liveRun.bullJob.data?.isIncremental),
        forceRefresh: false,
        alreadyRunning: true,
        message: "A sync is already running for this installation",
      });
    }

    // Create or update job for incremental/force refresh
    let job = await InstallationSummaryJob.findOneAndUpdate(
      jobFilter,
      {
        $setOnInsert: {
          tenantId,
          installationId,
          login: installation.account.login,
          accountId: installation.account.id,
          accountType: installation.account.type,
          createdAt: new Date(),
        },
        // `tenantId` stays out of `$set`: it is already seeded by `$setOnInsert`
        // and repeating it here conflicts (see startSummaryJob above).
        $set: {
          status: "pending",
          progress: 0,
          error: null,
          updatedAt: new Date(),
          ...(forceRefresh && { lastFetchedAt: null }), // Reset lastFetchedAt for force refresh
        },
      },
      { upsert: true, new: true }
    );
  console.log(
     {
      installationId,
      login: installation.account.login,
      accountId: installation.account.id,
      accountType: installation.account.type,
      mongoJobId: job._id,
      isIncremental: isIncremental,
      forceRefresh: forceRefresh,
    }
    );
    
    // Queue the job
    const bullJob = await summaryQueue.add('process-installation', {
      tenantId,
      installationId,
      login: installation.account.login,
      accountId: installation.account.id,
      accountType: installation.account.type,
      mongoJobId: job._id,
      isIncremental: isIncremental,
      forceRefresh: forceRefresh,
    }, {
      jobId: `refresh-${installationId}-${Date.now()}`,
      priority: forceRefresh ? 1 : 2, // Higher priority for force refresh
    });

    await InstallationSummaryJob.findByIdAndUpdate(job._id, {
      bullmqJobId: bullJob.id,
    });
  

    res.json({
      status: "refresh_started",
      jobId: job._id,
      bullmqJobId: bullJob.id,
      isIncremental: isIncremental,
      forceRefresh: forceRefresh,
      message: forceRefresh
        ? "Force refresh started - fetching all repositories from scratch"
        : isIncremental 
          ? "Incremental refresh started - fetching only updated repositories" 
          : "Full refresh started - this is the first sync",
    });
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, err.message));
  }
}

function normalizeSummary(summary = {}) {
  return {
    totals: {
      totalRepositories: summary?.totals?.totalRepositories || 0,
      totalBranches: summary?.totals?.totalBranches || 0,
      totalCommits: summary?.totals?.totalCommits || 0,
      totalForks: summary?.totals?.totalForks || 0,
      totalStars: summary?.totals?.totalStars || 0,
      totalPrivate: summary?.totals?.totalPrivate || 0,
      totalPublic: summary?.totals?.totalPublic || 0,
      totalInternal: summary?.totals?.totalInternal || 0,
      totalBytes: summary?.totals?.totalBytes || 0,
      totalArchivedRepos: summary?.totals?.totalArchivedRepos || 0,
      totalStaleBranches: summary?.totals?.totalStaleBranches || 0,
      totalTeams: summary?.totals?.totalTeams || 0,
      totalTeamMembers: summary?.totals?.totalTeamMembers || 0,
      totalSecurityEvents: summary?.totals?.totalSecurityEvents || 0,
      totalPatNoExpiry: summary?.totals?.totalPatNoExpiry || 0,
      totalPatExpired: summary?.totals?.totalPatExpired || 0,
      totalPatOverPermissive: summary?.totals?.totalPatOverPermissive || 0,
      totalExternalForks: summary?.totals?.totalExternalForks || 0,
    },
    languages: summary?.languages || [],
    repositories: summary?.repositories || [],
    teams: summary?.teams || [],
  };
}

module.exports = {
  startSummaryJob,
  getJobStatus,
  retryFailedJob,
  refreshInstallationData,
};
