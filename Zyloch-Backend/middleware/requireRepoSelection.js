const createError = require('../utils/createError');
const tenantScope = require('../helpers/tenantScope');
const { getSelectionState } = require('../services/repoSelection');

/**
 * Hold ingestion for an installation that has more repositories than its plan
 * covers until someone has chosen which ones Zyloch monitors.
 *
 * The block is deliberately server-side and stateless: the answer lives on the
 * installation document, so navigating away, signing out or coming back
 * tomorrow lands on the same gate. Answering with 409 + `REPO_SELECTION_REQUIRED`
 * (rather than a generic 403) is what lets the dashboard swap in the chooser
 * instead of showing a failure.
 */
async function requireRepoSelection(req, res, next) {
  try {
    const installationId = Number(req.params.installationId);
    if (!Number.isFinite(installationId) || installationId <= 0) return next();

    const installation = await tenantScope.assertInstallationBelongsToTenant(
      installationId,
      req.tenant.id
    );
    const state = await getSelectionState(installation, req.tenantId);

    if (state.selectionRequired) {
      const err = createError(
        409,
        `This installation has ${state.repoCount} repositories and your ` +
          `${state.planId || 'current'} plan covers ${state.limit}. ` +
          'Choose the repositories to monitor to finish setting up.'
      );
      err.code = 'REPO_SELECTION_REQUIRED';
      err.selection = state;
      return next(err);
    }

    req.repoSelection = state;
    return next();
  } catch (err) {
    return next(err);
  }
}

module.exports = requireRepoSelection;
