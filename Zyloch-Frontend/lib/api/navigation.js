export function replaceLocation(url) {
  if (typeof window !== "undefined" && url) {
    window.location.replace(url);
  }
}
