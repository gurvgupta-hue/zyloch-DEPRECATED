export const formatChartLabel = (value) => {
  if (value === null || value === undefined) return "";

  const normalized = String(value).replace(/\s+/g, " ").trim();

  // Preserve separators like '-' and '_' while capitalizing each token start.
  return normalized.replace(/(^|[\s_-])(\p{L})/gu, (match, sep, char) => `${sep}${char.toUpperCase()}`);
};
