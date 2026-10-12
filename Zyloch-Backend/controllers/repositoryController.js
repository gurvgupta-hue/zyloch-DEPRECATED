const createError = require("../utils/createError");
const { validatePositiveInteger } = require("../utils/validation");
const tenantScope = require("../helpers/tenantScope");

async function resolveInstallationScope(req) {
  const tenantId = req.tenant?.id || req.tenantId;
  const installationId = validatePositiveInteger(req.params.installationId, "installationId");
  const installation = await tenantScope.assertInstallationBelongsToTenant(
    installationId,
    tenantId
  );
  return {
    tenantId,
    installationId,
    accountLogin: installation.account.login,
    accountId: installation.account.id,
  };
}

function repositoryQuery({ tenantId, installationId, accountLogin, repositoryName }) {
  const query = { tenantId, installationId, login: accountLogin };
  if (repositoryName) {
    query.repositoryName = repositoryName;
  }
  return query;
}

/** Get repository data from database */
async function getRepositoryData(req, res, next) {
  try {
    const { login } = req.user || {};
    const { repositoryName } = req.query;

    if (!login) return next(createError(401, "Unauthorized"));

    const scope = await resolveInstallationScope(req);
    const RepositoryData = req.models.RepositoryData;

    if (repositoryName) {
      const repoData = await RepositoryData.findOne(
        repositoryQuery({ ...scope, repositoryName })
      );

      if (!repoData) {
        return next(createError(404, "Repository data not found"));
      }

      return res.json(repoData);
    }

    const reposData = await RepositoryData.find(
      repositoryQuery(scope)
    ).sort({ lastActive: -1 });

    res.json({
      count: reposData.length,
      repositories: reposData,
    });
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, err.message));
  }
}

/** Get branches for a specific repository */
async function getRepositoryBranches(req, res, next) {
  try {
    const { repositoryName } = req.params;
    const { login } = req.user || {};

    if (!login) return next(createError(401, "Unauthorized"));
    if (!repositoryName) return next(createError(400, "Repository name is required"));

    const scope = await resolveInstallationScope(req);
    const repoData = await req.models.RepositoryData.findOne(
      repositoryQuery({ ...scope, repositoryName })
    );

    if (!repoData) {
      return next(createError(404, "Repository not found"));
    }

    res.json({
      repositoryName: repoData.repositoryName,
      owner: repoData.owner,
      branches: repoData.branches || [],
      totalBranches: repoData.branches?.length || 0,
    });
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, err.message));
  }
}

/** Delete repository data */
async function deleteRepositoryData(req, res, next) {
  try {
    const { repositoryName } = req.params;
    const { login } = req.user || {};

    if (!login) return next(createError(401, "Unauthorized"));
    if (!repositoryName) return next(createError(400, "Repository name is required"));

    const scope = await resolveInstallationScope(req);
    const result = await req.models.RepositoryData.deleteOne(
      repositoryQuery({ ...scope, repositoryName })
    );

    if (result.deletedCount === 0) {
      return next(createError(404, "Repository not found"));
    }

    res.json({
      message: "Repository data deleted successfully",
      repositoryName,
    });
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, err.message));
  }
}

module.exports = {
  getRepositoryData,
  getRepositoryBranches,
  deleteRepositoryData,
  resolveInstallationScope,
  repositoryQuery,
};
