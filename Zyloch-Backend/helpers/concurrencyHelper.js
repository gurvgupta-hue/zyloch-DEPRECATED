// helpers/concurrencyHelper.js

/**
 * Run async tasks with a concurrency limit
 * @param {Array} items - Items to process
 * @param {number} limit - Max concurrent tasks
 * @param {Function} asyncFn - Async function to run on each item
 * @returns {Promise<Array>} - Results of each async function
 */
async function runWithConcurrencyLimit(items, limit, asyncFn) {
  const results = [];
  let i = 0;

  async function worker() {
    while (i < items.length) {
      const index = i++;
      try {
        results[index] = await asyncFn(items[index]);
      } catch (err) {
        results[index] = null; // ignore failures
      }
    }
  }

  const workers = [];
  for (let j = 0; j < Math.min(limit, items.length); j++) {
    workers.push(worker());
  }

  await Promise.all(workers);
  return results;
}

module.exports = { runWithConcurrencyLimit };
