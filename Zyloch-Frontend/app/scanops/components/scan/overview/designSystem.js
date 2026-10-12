export const OVERVIEW_DS = {
    colors: {
        primary: "#0EA5E9",
        secondary: "#14B8A6",
        accent: "#F59E0B",
        backgroundLight: "#F8FAFC",
        backgroundDark: "#0B1220",
    },
    typography: {
        family: "var(--font-ui)",
        headingLg: "32px",
        headingMd: "24px",
        headingSm: "16px",
        body: "14px",
        bodyLineHeight: "22px",
        label: "11px",
        micro: "10px",
        eyebrow: "11px",
    },
    spacing: {
        x1: "8px",
        x2: "16px",
        x3: "24px",
        x4: "32px",
        xs: "8px",
        sm: "16px",
        md: "24px",
    },
    radius: {
        sm: "8px",
        md: "12px",
        lg: "16px",
        pill: "9999px",
    },
};

export const OVERVIEW_CARD_STYLE = {
    background: "var(--surface)",
    border: "1px solid var(--border)",
    borderRadius: OVERVIEW_DS.radius.lg,
    boxShadow: "var(--shadow-1)",
    transition: "transform var(--transition-fast), box-shadow var(--transition-fast)",
};

export const OVERVIEW_EYEBROW_STYLE = {
    fontFamily: OVERVIEW_DS.typography.family,
    fontWeight: 700,
    fontSize: OVERVIEW_DS.typography.eyebrow,
    lineHeight: "16px",
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    color: "var(--muted)",
    margin: 0,
};