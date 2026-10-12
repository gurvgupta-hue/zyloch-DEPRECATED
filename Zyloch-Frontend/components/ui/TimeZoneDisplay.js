import { useTheme } from "@/context/ThemeContext";

export default function TimeZoneDisplay({ time, format = "full" }) {
  const { timeZone } = useTheme();

  if (!time) return null;

  // ✅ Ensure UTC parsing
  const date =
    typeof time === "string" && !time.endsWith("Z")
      ? new Date(`${time}Z`)
      : new Date(time);

  if (isNaN(date.getTime())) {
    return <span>Invalid date</span>;
  }

  const baseOptions = {
    timeZone, // ✅ convert UTC → selected timezone
  };

  const optionsMap = {
    date: {
      ...baseOptions,
      year: "numeric",
      month: "long",
      day: "numeric",
    },
    time: {
      ...baseOptions,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    },
    short: {
      ...baseOptions,
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    },
    full: {
      ...baseOptions,
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    },
  };

  return (
    <span>
      {date.toLocaleString("en-US", optionsMap[format] || optionsMap.full)}
    </span>
  );
}
